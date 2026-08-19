from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any

import re

app = FastAPI()


class ReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    target: str
    event: str
    ref: str
    workflow: Dict[str, Any]
    image: Dict[str, Any]


SHA40 = re.compile(r"^[0-9a-f]{40}$")


@app.get("/")
def home():
    return {"status": "Release Gate API is running"}


@app.post("/release-gate")
@app.post("/release_gate")
def release_gate(data: ReleaseRequest):
    
    violations = []

    workflow = data.workflow
    image = data.image

    # ---------------------------------------------------------
    # 1. EXACT LEAST-PRIVILEGE PERMISSIONS
    # ---------------------------------------------------------

    permissions = workflow.get("permissions", {})

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. SAFE PULL REQUEST TRIGGER
    # ---------------------------------------------------------

    trigger = workflow.get("trigger")

    if data.event == "pull_request":
        if trigger != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    if trigger == "pull_request_target":
        if "UNSAFE_PR_TRIGGER" not in violations:
            violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # 3. TESTS / MATRIX MUST BE COMPLETE
    # ---------------------------------------------------------

    tests_passed = workflow.get("testsPassed")
    matrix_complete = workflow.get("matrixComplete")
    fail_fast = workflow.get("failFast")

    if (
        tests_passed is not True
        or matrix_complete is not True
        or fail_fast is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 4. THIRD-PARTY ACTIONS MUST BE PINNED TO FULL SHA
    # ---------------------------------------------------------

    actions = workflow.get("actions", [])

    for action in actions:

        owner = action.get("owner", "")
        ref = action.get("ref", "")

        # GitHub-owned actions may use tags such as v4
        if owner == "actions":
            continue

        # Third-party action must use full lowercase 40-char SHA
        if not isinstance(ref, str) or SHA40.fullmatch(ref) is None:
            if "MUTABLE_ACTION" not in violations:
                violations.append("MUTABLE_ACTION")

    # ---------------------------------------------------------
    # 5. IMAGE MUST BE MULTI-STAGE
    # ---------------------------------------------------------

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # ---------------------------------------------------------
    # 6. CONTAINER MUST NOT RUN AS ROOT
    # ---------------------------------------------------------

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # ---------------------------------------------------------
    # 7. NO SECRET IN IMAGE LAYER
    # ---------------------------------------------------------

    secret_mode = image.get("secretMode")

    # Allowed:
    # none     -> no build secret
    # buildkit -> BuildKit secret mount
    #
    # Unsafe:
    # arg
    # copy

    if secret_mode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    # ---------------------------------------------------------
    # 8. ZERO CRITICAL VULNERABILITIES
    # ---------------------------------------------------------

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # ---------------------------------------------------------
    # 9. IMAGE MUST BE REFERENCED BY DIGEST
    # ---------------------------------------------------------

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 10. EXTRA PRODUCTION RULES
    # ---------------------------------------------------------

    if data.target == "production":

        if (
            data.event != "push"
            or data.ref != "refs/heads/main"
            or trigger != "push"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # FINAL DECISION
    # ---------------------------------------------------------

    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations
    }
from urllib.parse import urlparse
import re


ALLOWED_TENANT = "tenant-6hekv7t"
ALLOWED_EMAIL_DOMAIN = "notify-c29oo3y.example"

EVENT_HANDLER_RE = re.compile(r'on[a-zA-Z]+\s*=', re.IGNORECASE)
JAVASCRIPT_URL_RE = re.compile(r'javascript\s*:', re.IGNORECASE)
SCRIPT_RE = re.compile(r'<\s*script\b', re.IGNORECASE)
IFRAME_RE = re.compile(r'<\s*iframe\b', re.IGNORECASE)


def exact_keys(obj, expected_keys):
    return isinstance(obj, dict) and set(obj.keys()) == set(expected_keys)


@app.post("/action-firewall")
def action_firewall(payload: dict):

    # 1. TOP-LEVEL SCHEMA
    if not exact_keys(
        payload,
        {"provenance", "humanApproved", "action"}
    ) and not exact_keys(
        payload,
        {"provenance", "humanApproved", "untrustedContent", "action"}
    ):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    if payload.get("provenance") not in ["trusted", "untrusted"]:
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    if not isinstance(payload.get("humanApproved"), bool):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    if "untrustedContent" in payload and not isinstance(
        payload["untrustedContent"], str
    ):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    action = payload.get("action")

    if not exact_keys(action, {"tool", "args"}):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    if not isinstance(action["tool"], str):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    if not isinstance(action["args"], dict):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    tool = action["tool"]
    args = action["args"]

    # 2. TOOL ALLOWLIST
    allowed_tools = {
        "search",
        "lookup_record",
        "send_email",
        "render_html"
    }

    if tool not in allowed_tools:
        return {
            "decision": "block",
            "reason": "TOOL_NOT_ALLOWED"
        }

    # 3. TOOL ARGUMENT SCHEMA

    if tool == "search":

        if not exact_keys(args, {"query"}):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

        query = args.get("query")

        if (
            not isinstance(query, str)
            or len(query) < 1
            or len(query) > 200
        ):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "lookup_record":

        if not exact_keys(args, {"tenantId", "recordId"}):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

        if (
            not isinstance(args.get("tenantId"), str)
            or not isinstance(args.get("recordId"), str)
            or len(args["recordId"]) == 0
        ):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "send_email":

        if not exact_keys(args, {"to", "subject", "body"}):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

        if not all(
            isinstance(args.get(k), str)
            for k in ["to", "subject", "body"]
        ):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "render_html":

        if not exact_keys(args, {"html"}):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

        if not isinstance(args.get("html"), str):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    # 4. TENANT SCOPE
    if tool == "lookup_record":
        if args["tenantId"] != ALLOWED_TENANT:
            return {
                "decision": "block",
                "reason": "TENANT_SCOPE"
            }

    # 5. EXACT EMAIL DOMAIN
    if tool == "send_email":

        recipient = args["to"]

        if recipient.count("@") != 1:
            return {
                "decision": "block",
                "reason": "EGRESS_DENIED"
            }

        local_part, domain = recipient.rsplit("@", 1)

        if (
            not local_part
            or domain != ALLOWED_EMAIL_DOMAIN
        ):
            return {
                "decision": "block",
                "reason": "EGRESS_DENIED"
            }

    # 6. HUMAN APPROVAL
    if tool == "send_email":
        if payload["humanApproved"] is not True:
            return {
                "decision": "block",
                "reason": "APPROVAL_REQUIRED"
            }

    # 7. HTML SAFETY
    if tool == "render_html":

        html = args["html"]

        unsafe = (
            SCRIPT_RE.search(html)
            or IFRAME_RE.search(html)
            or EVENT_HANDLER_RE.search(html)
            or JAVASCRIPT_URL_RE.search(html)
        )

        if unsafe:
            return {
                "decision": "block",
                "reason": "UNSAFE_OUTPUT"
            }

    return {
        "decision": "allow",
        "reason": "ALLOW"
    }

PROD_WORKSPACE = "prod-he204n"

REQUIRED_LABELS = {
    "owner": "student-muicl",
    "environment": "production",
    "cost_center": "cc-do8d"
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}

STATEFUL_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk"
}

ALLOWED_ACTIONS = {
    "create",
    "update",
    "delete"
}


def terraform_invalid():
    return {
        "decision": "reject",
        "reason": "INVALID_PLAN"
    }


@app.post("/terraform/plan")
def terraform_plan(payload: dict):

    # ---------------------------------------------------------
    # 1. VALIDATE REQUEST AND NESTED VALUE TYPES
    # ---------------------------------------------------------

    if not isinstance(payload, dict):
        return terraform_invalid()

    expected_top_keys = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource"
    }

    if set(payload.keys()) != expected_top_keys:
        return terraform_invalid()

    if not isinstance(payload.get("environment"), str):
        return terraform_invalid()

    if not isinstance(payload.get("providerVersion"), str):
        return terraform_invalid()

    if not isinstance(payload.get("destroyApproved"), bool):
        return terraform_invalid()

    state = payload.get("state")

    if not isinstance(state, dict):
        return terraform_invalid()

    if set(state.keys()) != {"backend", "locked"}:
        return terraform_invalid()

    if not isinstance(state.get("backend"), str):
        return terraform_invalid()

    if not isinstance(state.get("locked"), bool):
        return terraform_invalid()

    resource = payload.get("resource")

    if not isinstance(resource, dict):
        return terraform_invalid()

    expected_resource_keys = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy"
    }

    if set(resource.keys()) != expected_resource_keys:
        return terraform_invalid()

    if not isinstance(resource.get("address"), str):
        return terraform_invalid()

    if not resource["address"]:
        return terraform_invalid()

    if not isinstance(resource.get("type"), str):
        return terraform_invalid()

    if not resource["type"]:
        return terraform_invalid()

    if not isinstance(resource.get("action"), str):
        return terraform_invalid()

    if resource["action"] not in ALLOWED_ACTIONS:
        return terraform_invalid()

    labels = resource.get("labels")

    if not isinstance(labels, dict):
        return terraform_invalid()

    # label keys and values must be strings
    for key, value in labels.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return terraform_invalid()

    secret = resource.get("secret")

    if secret is not None and not isinstance(secret, str):
        return terraform_invalid()

    if not isinstance(resource.get("forceDestroy"), bool):
        return terraform_invalid()

    # ---------------------------------------------------------
    # 2. ENVIRONMENT
    # ---------------------------------------------------------

    if payload["environment"] != PROD_WORKSPACE:
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH"
        }

    # ---------------------------------------------------------
    # 3. REMOTE STATE + LOCKING
    # ---------------------------------------------------------

    if (
        state["backend"] not in ALLOWED_BACKENDS
        or state["locked"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        }

    # ---------------------------------------------------------
    # 4. PROVIDER PINNING
    # ---------------------------------------------------------

    provider_version = payload["providerVersion"].strip()

    allowed_provider_versions = {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0"
    }

    if provider_version not in allowed_provider_versions:
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        }

    # ---------------------------------------------------------
    # 5. REQUIRED LABELS
    # ---------------------------------------------------------

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS"
            }

    # ---------------------------------------------------------
    # 6. SECRET SAFETY
    # ---------------------------------------------------------

    if secret is not None:

        if (
            len(secret) == 0
            or not secret.startswith("secret://")
            or len(secret) <= len("secret://")
        ):
            return {
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            }

    # ---------------------------------------------------------
    # 7. STATEFUL DELETE APPROVAL
    # ---------------------------------------------------------

    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_TYPES
        and payload["destroyApproved"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED"
        }

    # ---------------------------------------------------------
    # 8. PRODUCTION STORAGE BUCKET FORCE DESTROY
    # ---------------------------------------------------------

    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return {
            "decision": "reject",
            "reason": "FORCE_DESTROY"
        }

    # ---------------------------------------------------------
    # APPROVE
    # ---------------------------------------------------------

    return {
        "decision": "approve",
        "reason": "APPROVE"
    }
