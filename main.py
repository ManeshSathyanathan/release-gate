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
