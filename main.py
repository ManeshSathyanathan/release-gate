from fastapi import FastAPI, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any

import hashlib
import json
import math
import re
import unicodedata
import copy
import threading

from fastapi import Body
from fastapi.responses import JSONResponse



from datetime import datetime, timezone
from typing import Any


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

from urllib.parse import unquote, urlparse
from html import unescape
import re


OUTPUT_ALLOWED_HOSTS = {
    "cdn-ui4yoos.example",
    "app-k46ex9k.example"
}

VALID_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell"
}


SCRIPT_TAG_RE = re.compile(
    r"<\s*(script|iframe|object|embed)\b",
    re.IGNORECASE
)

EVENT_HANDLER_RE_2 = re.compile(
    r"\bon[a-z0-9_-]+\s*=",
    re.IGNORECASE
)

DANGEROUS_SCHEME_TEXT_RE = re.compile(
    r"\b(javascript|data|vbscript)\s*:",
    re.IGNORECASE
)

HTML_URL_RE = re.compile(
    r"\b(?:src|href)\s*=\s*([\"'])(.*?)\1",
    re.IGNORECASE | re.DOTALL
)

MARKDOWN_URL_RE = re.compile(
    r"\]\(([^)]+)\)"
)

SQL_META_RE = re.compile(
    r"""['";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b""",
    re.IGNORECASE
)

SHELL_META_RE = re.compile(
    r";|&|\||`|<|>|\$\(|\$\{"
)

UNICODE_ESCAPE_RE = re.compile(
    r"\\u([0-9a-fA-F]{4})"
)


def decode_once(text: str) -> str:
    # Required order:
    # 1. percent escapes
    # 2. HTML entities
    # 3. \uXXXX escapes

    decoded = unquote(text)
    decoded = unescape(decoded)

    decoded = UNICODE_ESCAPE_RE.sub(
        lambda m: chr(int(m.group(1), 16)),
        decoded
    )

    return decoded


def extract_urls(channel: str, text: str):
    urls = []

    if channel == "html":
        for match in HTML_URL_RE.finditer(text):
            urls.append(match.group(2).strip())

    elif channel == "markdown":
        for match in MARKDOWN_URL_RE.finditer(text):
            target = match.group(1).strip()

            # Handle common markdown form:
            # ](https://host/path "optional title")
            if target.startswith("<") and ">" in target:
                target = target[1:target.index(">")]
            else:
                target = target.split()[0] if target else ""

            urls.append(target)

    elif channel == "url":
        urls.append(text.strip())

    return urls


def classify_url_problem(raw_url: str):
    url = raw_url.strip()

    if not url:
        return None

    # Explicit dangerous textual schemes
    if DANGEROUS_SCHEME_TEXT_RE.search(url):
        return "DANGEROUS_SCHEME"

    # Protocol-relative references are absolute.
    if url.startswith("//"):
        parsed = urlparse("https:" + url)

        if parsed.hostname not in OUTPUT_ALLOWED_HOSTS:
            return "EXTERNAL_EXFIL"

        return None

    parsed = urlparse(url)

    # Absolute URL with a scheme
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"}:
            return "DANGEROUS_SCHEME"

        hostname = parsed.hostname

        if hostname not in OUTPUT_ALLOWED_HOSTS:
            return "EXTERNAL_EXFIL"

    # Relative URLs are allowed
    return None


def channel_rule_reason(channel: str, text: str):
    # HTML rule order
    if channel == "html":

        if SCRIPT_TAG_RE.search(text):
            return "SCRIPT_TAG"

        if EVENT_HANDLER_RE_2.search(text):
            return "EVENT_HANDLER"

        if DANGEROUS_SCHEME_TEXT_RE.search(text):
            return "DANGEROUS_SCHEME"

        urls = extract_urls("html", text)

        for url in urls:
            problem = classify_url_problem(url)

            if problem == "DANGEROUS_SCHEME":
                return "DANGEROUS_SCHEME"

        for url in urls:
            problem = classify_url_problem(url)

            if problem == "EXTERNAL_EXFIL":
                return "EXTERNAL_EXFIL"

        return None

    # Markdown rule order
    if channel == "markdown":

        if DANGEROUS_SCHEME_TEXT_RE.search(text):
            return "DANGEROUS_SCHEME"

        urls = extract_urls("markdown", text)

        for url in urls:
            problem = classify_url_problem(url)

            if problem == "DANGEROUS_SCHEME":
                return "DANGEROUS_SCHEME"

        for url in urls:
            problem = classify_url_problem(url)

            if problem == "EXTERNAL_EXFIL":
                return "EXTERNAL_EXFIL"

        return None

    # URL rule order
    if channel == "url":

        if DANGEROUS_SCHEME_TEXT_RE.search(text):
            return "DANGEROUS_SCHEME"

        problem = classify_url_problem(text.strip())

        if problem:
            return problem

        return None

    # SQL
    if channel == "sql":

        if SQL_META_RE.search(text):
            return "SQL_METACHAR"

        return None

    # Shell
    if channel == "shell":

        if SHELL_META_RE.search(text):
            return "SHELL_METACHAR"

        return None

    return None


@app.post("/sanitize-output")
def sanitize_output(payload: dict):

    # ---------------------------------------------------------
    # 1. INVALID_SCHEMA
    # ---------------------------------------------------------

    if not isinstance(payload, dict):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if set(payload.keys()) != {"channel", "output"}:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    channel = payload.get("channel")
    output = payload.get("output")

    if channel not in VALID_CHANNELS:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if not isinstance(output, str):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if len(output) > 20000:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    # ---------------------------------------------------------
    # 2. ENCODED_PAYLOAD
    # ---------------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = channel_rule_reason(channel, decoded)

        if decoded_reason is not None:
            return {
                "safe": False,
                "reason": "ENCODED_PAYLOAD"
            }

    # ---------------------------------------------------------
    # 3. ORIGINAL OUTPUT CHANNEL RULES
    # ---------------------------------------------------------

    reason = channel_rule_reason(channel, output)

    if reason is not None:
        return {
            "safe": False,
            "reason": reason
        }

    # ---------------------------------------------------------
    # SAFE
    # ---------------------------------------------------------

    return {
        "safe": True,
        "reason": "SAFE"
    }

from datetime import datetime, timezone


OSINT_ALLOWED_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan"
}


def parse_iso8601(value):
    if not isinstance(value, str):
        return None

    try:
        # Support trailing Z
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        dt = datetime.fromisoformat(value)

        # Require timezone information
        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except Exception:
        return None


def invalid_osint():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": []
    }


@app.post("/corroborate")
def corroborate(payload: Any = Body(...)):

    # ---------------------------------------------------------
    # 1. INVALID
    # ---------------------------------------------------------

    if not isinstance(payload, dict):
        return invalid_osint()

    claim = payload.get("claim")

    if not isinstance(claim, dict):
        return invalid_osint()

    claim_value = claim.get("value")

    if not isinstance(claim_value, str):
        return invalid_osint()

    as_of_raw = payload.get("asOf")
    as_of = parse_iso8601(as_of_raw)

    if as_of is None:
        return invalid_osint()

    staleness_days = payload.get("stalenessDays")

    # bool is a subclass of int in Python, so reject it explicitly
    if (
        isinstance(staleness_days, bool)
        or not isinstance(staleness_days, (int, float))
    ):
        return invalid_osint()

    sources = payload.get("sources")

    if not isinstance(sources, list):
        return invalid_osint()

    # ---------------------------------------------------------
    # PREPARE VALID FRESH SOURCES
    # ---------------------------------------------------------

    valid_fresh_sources = []

    for source in sources:

        if not isinstance(source, dict):
            continue

        source_id = source.get("id")
        source_origin = source.get("origin")
        source_value = source.get("value")
        observed_raw = source.get("observedAt")
        source_type = source.get("type")

        # Valid source definition
        if not isinstance(source_id, str):
            continue

        if not isinstance(source_origin, str):
            continue

        if not isinstance(source_value, str):
            continue

        if not isinstance(observed_raw, str):
            continue

        if source_type not in OSINT_ALLOWED_TYPES:
            continue

        observed_at = parse_iso8601(observed_raw)

        if observed_at is None:
            continue

        # Fresh means:
        # asOf - observedAt <= stalenessDays
        age_seconds = (as_of - observed_at).total_seconds()
        max_age_seconds = staleness_days * 86400

        if age_seconds > max_age_seconds:
            continue

        valid_fresh_sources.append({
            "id": source_id,
            "origin": source_origin,
            "value": source_value,
            "type": source_type,
            "authoritative": source.get("authoritative") is True
        })

    # ---------------------------------------------------------
    # 2. AUTHORITATIVE CONTRADICTION
    # ---------------------------------------------------------

    contradicting_ids = []

    for source in valid_fresh_sources:
        if (
            source["authoritative"] is True
            and source["value"] != claim_value
        ):
            contradicting_ids.append(source["id"])

    if contradicting_ids:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradicting_ids)
        }

    # ---------------------------------------------------------
    # 3. SUPPORTED
    # Keep only fresh matching sources and reduce to one
    # representative per origin.
    # Representative = lexicographically smallest source id.
    # ---------------------------------------------------------

    matching_sources = [
        source
        for source in valid_fresh_sources
        if source["value"] == claim_value
    ]

    representatives_by_origin = {}

    for source in matching_sources:

        origin = source["origin"]

        if origin not in representatives_by_origin:
            representatives_by_origin[origin] = source
        else:
            current = representatives_by_origin[origin]

            if source["id"] < current["id"]:
                representatives_by_origin[origin] = source

    representatives = list(representatives_by_origin.values())

    if len(representatives) >= 2:

        representative_ids = sorted(
            source["id"]
            for source in representatives
        )

        representative_types = {
            source["type"]
            for source in representatives
        }

        confidence = (
            "high"
            if len(representative_types) >= 2
            else "medium"
        )

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": representative_ids
        }

    # ---------------------------------------------------------
    # 4. UNVERIFIED
    # ---------------------------------------------------------

    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    }

# ============================================================
# IMMUTABLE, LEAKAGE-SAFE TRAINING CORPUS
# ============================================================

CORPUS_URI_RE = re.compile(r"^gs://[^/\s]+/.+$")
CORPUS_GENERATION_RE = re.compile(r"^[0-9]+$")
CORPUS_CRC_RE = re.compile(r"^[0-9a-f]{8}$")

CORPUS_TIME_RE = re.compile(
    r"^"
    r"(\d{4})-(\d{2})-(\d{2})"
    r"T"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})"
    r"$"
)


# ------------------------------------------------------------
# CRC32C (Castagnoli)
# NOT normal zlib.crc32
# ------------------------------------------------------------

def corpus_crc32c(data: bytes) -> str:
    crc = 0xFFFFFFFF
    polynomial = 0x82F63B78

    for byte in data:
        crc ^= byte

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ polynomial
            else:
                crc >>= 1

    crc ^= 0xFFFFFFFF

    return f"{crc:08x}"


# ------------------------------------------------------------
# STRICT TIMESTAMP PARSER
# ------------------------------------------------------------

def corpus_parse_time(value):
    if not isinstance(value, str):
        return None

    match = CORPUS_TIME_RE.fullmatch(value)

    if not match:
        return None

    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    hour = int(match.group(4))
    minute = int(match.group(5))
    second = int(match.group(6))

    fraction = match.group(7)
    offset_text = match.group(8)

    if fraction is None:
        microsecond = 0
    else:
        # 1-3 digits -> milliseconds
        fraction = fraction.ljust(3, "0")
        microsecond = int(fraction) * 1000

    # Validate timezone offset
    if offset_text == "Z":
        offset = timezone.utc
    else:
        sign = 1 if offset_text[0] == "+" else -1

        offset_hour = int(offset_text[1:3])
        offset_minute = int(offset_text[4:6])

        if offset_minute > 59:
            return None

        if offset_hour > 14:
            return None

        if offset_hour == 14 and offset_minute != 0:
            return None

        from datetime import timedelta

        offset = timezone(
            sign * timedelta(
                hours=offset_hour,
                minutes=offset_minute
            )
        )

    try:
        parsed = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
            tzinfo=offset
        )
    except ValueError:
        return None

    return parsed.astimezone(timezone.utc)


def corpus_format_time(dt):
    milliseconds = dt.microsecond // 1000

    return (
        dt.strftime("%Y-%m-%dT%H:%M:%S")
        + f".{milliseconds:03d}Z"
    )


# ------------------------------------------------------------
# CANONICAL TEXT
# ------------------------------------------------------------

def corpus_canonicalize(value):
    value = unicodedata.normalize("NFKC", value)
    value = value.lower()
    value = value.strip()

    # Collapse all Unicode whitespace to one ASCII space
    return " ".join(value.split())


# ------------------------------------------------------------
# WORD SET
#
# Words consist only of Unicode letters/numbers.
# ------------------------------------------------------------

def corpus_word_set(text):
    words = set()
    current = []

    for ch in text.lower():
        category = unicodedata.category(ch)

        if category.startswith("L") or category.startswith("N"):
            current.append(ch)
        else:
            if current:
                words.add("".join(current))
                current = []

    if current:
        words.add("".join(current))

    return words


def corpus_jaccard(a, b):
    a_words = corpus_word_set(a)
    b_words = corpus_word_set(b)

    if not a_words and not b_words:
        return 1.0

    union = a_words | b_words

    if not union:
        return 1.0

    return len(a_words & b_words) / len(union)


# ------------------------------------------------------------
# COMPACT JSON
# ------------------------------------------------------------

def corpus_compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


# ------------------------------------------------------------
# SORT HELPER
# ------------------------------------------------------------

def corpus_utf8(value):
    return value.encode("utf-8")


# ------------------------------------------------------------
# POLICY VALIDATION
# ------------------------------------------------------------

def corpus_validate_policy(policy):
    if not isinstance(policy, dict):
        return None

    min_raw = policy.get("minTime")
    max_raw = policy.get("maxTime")
    threshold = policy.get("contaminationThreshold")

    min_time = corpus_parse_time(min_raw)
    max_time = corpus_parse_time(max_raw)

    if min_time is None or max_time is None:
        return None

    # bool must not count as number
    if isinstance(threshold, bool):
        return None

    if not isinstance(threshold, (int, float)):
        return None

    if not math.isfinite(threshold):
        return None

    if threshold < 0 or threshold > 1:
        return None

    if min_time > max_time:
        return None

    return {
        "minTime": min_time,
        "maxTime": max_time,
        "threshold": float(threshold)
    }


# ------------------------------------------------------------
# MAIN ENDPOINT
# ------------------------------------------------------------

@app.post("/build-corpus")
def build_corpus(payload: Any = Body(...)):

    # ========================================================
    # INPUT-LEVEL VALIDATION
    # ========================================================

    if not isinstance(payload, dict):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    if "policy" not in payload:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    objects = payload.get("objects")

    if not isinstance(objects, list):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    policy = payload.get("policy")
    valid_policy = corpus_validate_policy(policy)

    rejected_objects = []
    rejected_rows = []
    lineage = []

    all_valid_rows = []

    # ========================================================
    # 1. OBJECT VALIDATION
    # ========================================================

    for object_index, obj in enumerate(objects):

        reason_codes = []

        if not isinstance(obj, dict):
            rejected_objects.append({
                "uri": None,
                "reasonCodes": [
                    "CRC32C_INVALID",
                    "GENERATION_INVALID",
                    "JSONL_INVALID",
                    "SCHEMA_INVALID",
                    "URI_INVALID"
                ]
            })
            continue

        uri = obj.get("uri")
        generation = obj.get("generation")
        fetched_generation = obj.get("fetchedGeneration")
        crc32c_value = obj.get("crc32c")
        schema_id = obj.get("schemaId")
        content = obj.get("content")

        # URI
        if (
            not isinstance(uri, str)
            or CORPUS_URI_RE.fullmatch(uri) is None
        ):
            reason_codes.append("URI_INVALID")

        # Generation syntax
        generation_valid = (
            isinstance(generation, str)
            and CORPUS_GENERATION_RE.fullmatch(generation) is not None
        )

        fetched_generation_valid = (
            isinstance(fetched_generation, str)
            and CORPUS_GENERATION_RE.fullmatch(
                fetched_generation
            ) is not None
        )

        if not generation_valid or not fetched_generation_valid:
            reason_codes.append("GENERATION_INVALID")

        # Mismatch applies to unequal supplied values
        if generation != fetched_generation:
            reason_codes.append("GENERATION_MISMATCH")

        # CRC syntax
        crc_syntax_valid = (
            isinstance(crc32c_value, str)
            and CORPUS_CRC_RE.fullmatch(crc32c_value) is not None
        )

        if not crc_syntax_valid:
            reason_codes.append("CRC32C_INVALID")

        # CRC mismatch only when content string + valid CRC syntax
        if isinstance(content, str) and crc_syntax_valid:
            actual_crc = corpus_crc32c(
                content.encode("utf-8")
            )

            if actual_crc != crc32c_value:
                reason_codes.append("CRC32C_MISMATCH")

        # Schema / content
        if schema_id != "training-v1":
            reason_codes.append("SCHEMA_INVALID")

        if not isinstance(content, str):
            reason_codes.append("SCHEMA_INVALID")

        parsed_rows = []

        # JSONL validation
        if isinstance(content, str):

            nonblank_count = 0
            parse_failed = False
            schema_failed = False

            for line in content.splitlines():

                if line.strip() == "":
                    continue

                nonblank_count += 1

                try:
                    row = json.loads(line)
                except Exception:
                    parse_failed = True
                    continue

                if not isinstance(row, dict):
                    schema_failed = True
                    continue

                expected_keys = {
                    "id",
                    "entity",
                    "eventTime",
                    "revision",
                    "text"
                }

                if set(row.keys()) != expected_keys:
                    schema_failed = True
                    continue

                # Four text fields
                if not isinstance(row.get("id"), str):
                    schema_failed = True
                    continue

                if not isinstance(row.get("entity"), str):
                    schema_failed = True
                    continue

                if not isinstance(row.get("eventTime"), str):
                    schema_failed = True
                    continue

                if not isinstance(row.get("text"), str):
                    schema_failed = True
                    continue

                revision = row.get("revision")

                # non-negative JavaScript safe integer
                if (
                    isinstance(revision, bool)
                    or not isinstance(revision, int)
                    or revision < 0
                    or revision > 9007199254740991
                ):
                    schema_failed = True
                    continue

                event_dt = corpus_parse_time(
                    row["eventTime"]
                )

                if event_dt is None:
                    schema_failed = True
                    continue

                parsed_rows.append({
                    "id": row["id"],
                    "entity": corpus_canonicalize(
                        row["entity"]
                    ),
                    "eventTime": corpus_format_time(
                        event_dt
                    ),
                    "eventDateTime": event_dt,
                    "revision": revision,
                    "text": corpus_canonicalize(
                        row["text"]
                    ),
                    "_objectIndex": object_index
                })

            if parse_failed:
                reason_codes.append("JSONL_INVALID")

            if nonblank_count == 0:
                reason_codes.append("SCHEMA_INVALID")

            if schema_failed:
                reason_codes.append("SCHEMA_INVALID")

        # Deduplicate / sort object reason codes
        reason_codes = sorted(
            set(reason_codes),
            key=lambda x: x.encode("utf-8")
        )

        # Reject whole object if ANY object failure
        if reason_codes:
            rejected_objects.append({
                "uri": uri if isinstance(uri, str) else None,
                "reasonCodes": reason_codes
            })

            continue

        # Object accepted
        lineage.append({
            "uri": uri,
            "generation": generation,
            "crc32c": crc32c_value,
            "schemaId": schema_id
        })

        all_valid_rows.extend(parsed_rows)

    # ========================================================
    # 2. DEDUPLICATE
    #
    # key = JSON tuple [entity,eventTime,text]
    #
    # highest revision wins
    # then UTF-8-byte-smallest ID
    # ========================================================

    groups = {}

    for row in all_valid_rows:
        duplicate_key = (
            row["entity"],
            row["eventTime"],
            row["text"]
        )

        groups.setdefault(
            duplicate_key,
            []
        ).append(row)

    retained_rows = []

    for _, rows in groups.items():

        rows_sorted = sorted(
            rows,
            key=lambda row: (
                -row["revision"],
                row["id"].encode("utf-8")
            )
        )

        winner = rows_sorted[0]
        retained_rows.append(winner)

        for loser in rows_sorted[1:]:
            rejected_rows.append({
                "id": loser["id"],
                "reasonCodes": ["DUPLICATE"]
            })

    # ========================================================
    # 3/4. POLICY
    # ========================================================

    policy_passed_rows = []

    if valid_policy is None:

        for row in retained_rows:
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": ["POLICY_INVALID"]
            })

    else:

        min_time = valid_policy["minTime"]
        max_time = valid_policy["maxTime"]

        for row in retained_rows:

            event_time = row["eventDateTime"]

            if event_time < min_time or event_time > max_time:
                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": ["OUT_OF_WINDOW"]
                })
            else:
                policy_passed_rows.append(row)

    # ========================================================
    # 5. SPLIT
    # ========================================================

    train_rows = []
    validation_candidates = []
    test_candidates = []

    if valid_policy is not None:

        for row in policy_passed_rows:

            entity_hash = hashlib.sha256(
                row["entity"].encode("utf-8")
            ).digest()

            bucket = entity_hash[0] % 10

            if bucket <= 5:
                train_rows.append(row)

            elif bucket <= 7:
                validation_candidates.append(row)

            else:
                test_candidates.append(row)

    # ========================================================
    # 6. TRAIN CONTAMINATION
    # ========================================================

    final_validation = []
    final_test = []

    threshold = (
        valid_policy["threshold"]
        if valid_policy is not None
        else None
    )

    if valid_policy is not None:

        for row in validation_candidates:

            contaminated = False

            for train_row in train_rows:
                similarity = corpus_jaccard(
                    row["text"],
                    train_row["text"]
                )

                if similarity >= threshold:
                    contaminated = True
                    break

            if contaminated:
                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": [
                        "TRAIN_CONTAMINATION"
                    ]
                })
            else:
                final_validation.append(row)

        for row in test_candidates:

            contaminated = False

            for train_row in train_rows:
                similarity = corpus_jaccard(
                    row["text"],
                    train_row["text"]
                )

                if similarity >= threshold:
                    contaminated = True
                    break

            if contaminated:
                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": [
                        "TRAIN_CONTAMINATION"
                    ]
                })
            else:
                final_test.append(row)

    # ========================================================
    # OUTPUT ROW CREATOR
    # exact key order:
    # id,entity,eventTime,revision,text
    # ========================================================

    def clean_row(row):
        return {
            "id": row["id"],
            "entity": row["entity"],
            "eventTime": row["eventTime"],
            "revision": row["revision"],
            "text": row["text"]
        }

    train_output = [
        clean_row(row)
        for row in train_rows
    ]

    validation_output = [
        clean_row(row)
        for row in final_validation
    ]

    test_output = [
        clean_row(row)
        for row in final_test
    ]

    # ========================================================
    # 7. DETERMINISTIC SORTING
    # ========================================================

    def row_sort_key(row):
        compact = corpus_compact_json(row)

        return (
            row["id"].encode("utf-8"),
            compact.encode("utf-8")
        )

    train_output.sort(key=row_sort_key)
    validation_output.sort(key=row_sort_key)
    test_output.sort(key=row_sort_key)

    # --------------------------------------------------------
    # rejectedRows:
    # merge same id/reasons, then sort
    # --------------------------------------------------------

    rejected_row_map = {}

    for item in rejected_rows:
        row_id = item["id"]

        rejected_row_map.setdefault(
            row_id,
            set()
        ).update(item["reasonCodes"])

    rejected_rows_output = []

    for row_id, reasons in rejected_row_map.items():
        rejected_rows_output.append({
            "id": row_id,
            "reasonCodes": sorted(
                reasons,
                key=lambda x: x.encode("utf-8")
            )
        })

    rejected_rows_output.sort(
        key=lambda item: (
            item["id"].encode("utf-8"),
            corpus_compact_json(item).encode("utf-8")
        )
    )

    # --------------------------------------------------------
    # rejectedObjects
    # --------------------------------------------------------

    for item in rejected_objects:
        item["reasonCodes"] = sorted(
            set(item["reasonCodes"]),
            key=lambda x: x.encode("utf-8")
        )

    def rejected_object_sort_key(item):
        uri = item["uri"]

        uri_bytes = (
            uri.encode("utf-8")
            if isinstance(uri, str)
            else b""
        )

        return (
            uri_bytes,
            corpus_compact_json(item).encode("utf-8")
        )

    rejected_objects.sort(
        key=rejected_object_sort_key
    )

    # --------------------------------------------------------
    # lineage
    # --------------------------------------------------------

    lineage.sort(
        key=lambda item: (
            item["uri"].encode("utf-8"),
            corpus_compact_json(item).encode("utf-8")
        )
    )

    # ========================================================
    # DIGESTS
    # ========================================================

    def split_digest(rows):

        serialized = ""

        for row in rows:
            serialized += corpus_compact_json(row)
            serialized += "\n"

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    digests = {
        "train": split_digest(train_output),
        "validation": split_digest(
            validation_output
        ),
        "test": split_digest(test_output)
    }

    # ========================================================
    # EXACT RESPONSE SHAPE
    # ========================================================

    return {
        "splits": {
            "train": train_output,
            "validation": validation_output,
            "test": test_output
        },
        "rejectedObjects": rejected_objects,
        "rejectedRows": rejected_rows_output,
        "digests": digests,
        "lineage": lineage
    }

# ============================================================
# BIGQUERY ML LEAKAGE-SAFE EXPERIMENT GATE
# ============================================================

BQLM_RUNS = {}
BQLM_LOCK = threading.Lock()

BQLM_SAFE_INT_MAX = 9007199254740991


def bqml_compact(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


def bqml_input_fingerprint(payload):
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True
        ).encode("utf-8")
    ).hexdigest()


def bqml_safe_int(value, non_negative=True):
    if isinstance(value, bool):
        return False

    if not isinstance(value, int):
        return False

    if value > BQLM_SAFE_INT_MAX:
        return False

    if non_negative and value < 0:
        return False

    return True


def bqml_finite_number(value):
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


def bqml_sorted_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: x.encode("utf-8")
    )


def bqml_utf8_sorted(values):
    return sorted(
        values,
        key=lambda x: x.encode("utf-8")
    )


def bqml_dataset_digest(train_ids, eval_ids, feature_names):
    # Exact key order required.
    data = {
        "trainRowIds": train_ids,
        "evalRowIds": eval_ids,
        "featureNames": feature_names
    }

    raw = bqml_compact(data).encode("utf-8")

    return hashlib.sha256(raw).hexdigest()


def bqml_select(payload):
    codes = []

    # --------------------------------------------------------
    # Basic selection input
    # --------------------------------------------------------

    run_id = payload.get("runId")

    if (
        not isinstance(run_id, str)
        or len(run_id) == 0
        or len(run_id) > 128
    ):
        codes.append("INVALID_INPUT")

    forbidden = payload.get("forbiddenFeatures")

    if (
        not isinstance(forbidden, list)
        or any(not isinstance(x, str) for x in forbidden)
    ):
        codes.append("INVALID_INPUT")
        forbidden = []

    num_trials_limit = payload.get("numTrialsLimit")

    if (
        not bqml_safe_int(num_trials_limit)
        or num_trials_limit <= 0
    ):
        codes.append("INVALID_INPUT")

    rows = payload.get("rows")
    trials = payload.get("trials")

    if not isinstance(rows, list) or len(rows) == 0:
        codes.append("INVALID_INPUT")
        rows = []

    if not isinstance(trials, list):
        codes.append("INVALID_INPUT")
        trials = []

    parsed_rows = []
    row_ids_seen = set()

    # --------------------------------------------------------
    # Validate selection rows
    # --------------------------------------------------------

    for row in rows:
        if not isinstance(row, dict):
            codes.append("INVALID_INPUT")
            continue

        required = {
            "id",
            "entity",
            "eventTime",
            "predictionTime",
            "version",
            "split",
            "features"
        }

        if set(row.keys()) != required:
            codes.append("INVALID_INPUT")
            continue

        row_id = row.get("id")
        entity = row.get("entity")
        event_raw = row.get("eventTime")
        pred_raw = row.get("predictionTime")
        version = row.get("version")
        split = row.get("split")
        features = row.get("features")

        if not isinstance(row_id, str) or len(row_id) == 0:
            codes.append("INVALID_INPUT")
            continue

        if row_id in row_ids_seen:
            codes.append("INVALID_INPUT")
            continue

        row_ids_seen.add(row_id)

        if not isinstance(entity, str):
            codes.append("INVALID_INPUT")
            continue

        if not bqml_safe_int(version):
            codes.append("INVALID_INPUT")
            continue

        if split not in {"TRAIN", "EVAL"}:
            codes.append("INVALID_INPUT")
            continue

        if not isinstance(features, dict):
            codes.append("INVALID_INPUT")
            continue

        # Reuse the strict timestamp parser from the corpus task.
        event_dt = corpus_parse_time(event_raw)
        prediction_dt = corpus_parse_time(pred_raw)

        if event_dt is None or prediction_dt is None:
            codes.append("INVALID_INPUT")
            continue

        parsed_features = {}
        bad_feature = False

        for feature_name, feature in features.items():
            if not isinstance(feature_name, str):
                bad_feature = True
                break

            if not isinstance(feature, dict):
                bad_feature = True
                break

            if set(feature.keys()) != {"value", "availableAt"}:
                bad_feature = True
                break

            available_raw = feature.get("availableAt")
            available_dt = corpus_parse_time(available_raw)

            if available_dt is None:
                bad_feature = True
                break

            # "value" is intentionally treated as data.
            parsed_features[feature_name] = {
                "value": feature.get("value"),
                "availableAt": available_dt
            }

        if bad_feature:
            codes.append("INVALID_INPUT")
            continue

        parsed_rows.append({
            "id": row_id,
            "entity": entity,
            "eventTime": event_dt,
            "eventTimeUTC": corpus_format_time(event_dt),
            "predictionTime": prediction_dt,
            "version": version,
            "split": split,
            "features": parsed_features
        })

    # --------------------------------------------------------
    # Validate trials
    # --------------------------------------------------------

    parsed_trials = []
    trial_ids_seen = set()

    for trial in trials:
        if not isinstance(trial, dict):
            codes.append("INVALID_INPUT")
            continue

        if set(trial.keys()) != {
            "trialId",
            "status",
            "evalMetric"
        }:
            codes.append("INVALID_INPUT")
            continue

        trial_id = trial.get("trialId")
        status = trial.get("status")
        metric = trial.get("evalMetric")

        if not bqml_safe_int(trial_id):
            codes.append("INVALID_INPUT")
            continue

        if trial_id in trial_ids_seen:
            codes.append("INVALID_INPUT")
            continue

        trial_ids_seen.add(trial_id)

        if status not in {"SUCCEEDED", "FAILED"}:
            codes.append("INVALID_INPUT")
            continue

        # Failed trials may have a non-finite / unusable metric;
        # only finite SUCCEEDED trials are selectable.
        if status == "SUCCEEDED":
            if not bqml_finite_number(metric):
                # Not malformed structurally; simply not eligible.
                parsed_trials.append({
                    "trialId": trial_id,
                    "status": status,
                    "evalMetric": None
                })
                continue

        parsed_trials.append({
            "trialId": trial_id,
            "status": status,
            "evalMetric": metric
        })

    # Trial-count contract check
    if (
        isinstance(num_trials_limit, int)
        and not isinstance(num_trials_limit, bool)
        and num_trials_limit > 0
        and len(trials) > num_trials_limit
    ):
        codes.append("TRIAL_LIMIT_EXCEEDED")

    malformed = "INVALID_INPUT" in codes

    train_ids = []
    eval_ids = []
    feature_names = []
    dataset_digest = None
    selected_trial_id = None

    # --------------------------------------------------------
    # Deduplicate and construct frozen selection dataset
    # only if structurally valid
    # --------------------------------------------------------

    if not malformed:
        groups = {}

        for row in parsed_rows:
            key = (
                row["entity"],
                row["eventTimeUTC"]
            )

            groups.setdefault(key, []).append(row)

        retained = []

        for group_rows in groups.values():
            group_rows.sort(
                key=lambda r: (
                    -r["version"],
                    r["id"].encode("utf-8")
                )
            )

            retained.append(group_rows[0])

        # TRAIN and EVAL only — never final-test rows.
        train_ids = bqml_utf8_sorted([
            r["id"]
            for r in retained
            if r["split"] == "TRAIN"
        ])

        eval_ids = bqml_utf8_sorted([
            r["id"]
            for r in retained
            if r["split"] == "EVAL"
        ])

        # ----------------------------------------------------
        # Eligible features:
        # appears in every retained row
        # not forbidden
        # availableAt <= predictionTime everywhere
        # ----------------------------------------------------

        if retained:
            candidate_features = set(
                retained[0]["features"].keys()
            )

            for row in retained[1:]:
                candidate_features &= set(
                    row["features"].keys()
                )

            forbidden_set = set(forbidden)

            eligible = []

            for feature_name in candidate_features:
                if feature_name in forbidden_set:
                    continue

                safe = True

                for row in retained:
                    feature = row["features"][feature_name]

                    if (
                        feature["availableAt"]
                        > row["predictionTime"]
                    ):
                        safe = False
                        break

                if safe:
                    eligible.append(feature_name)

            feature_names = bqml_utf8_sorted(eligible)

        dataset_digest = bqml_dataset_digest(
            train_ids,
            eval_ids,
            feature_names
        )

        # ----------------------------------------------------
        # Trial selection
        # ----------------------------------------------------

        successful = [
            t
            for t in parsed_trials
            if (
                t["status"] == "SUCCEEDED"
                and t["evalMetric"] is not None
                and bqml_finite_number(t["evalMetric"])
            )
        ]

        if not successful:
            codes.append("NO_SUCCESSFUL_TRIAL")

        if not codes:
            # Highest metric, then smallest trial ID.
            successful.sort(
                key=lambda t: (
                    -float(t["evalMetric"]),
                    t["trialId"]
                )
            )

            selected_trial_id = successful[0]["trialId"]

    codes = bqml_sorted_codes(codes)

    # Any code makes selectedTrialId null.
    if codes:
        selected_trial_id = None

    # Malformed selection => null datasetDigest.
    if malformed:
        dataset_digest = None

    return {
        "runId": run_id,
        "selectedTrialId": selected_trial_id,
        "trainRowIds": train_ids,
        "evalRowIds": eval_ids,
        "featureNames": feature_names,
        "datasetDigest": dataset_digest,
        "reasonCodes": codes
    }


def bqml_evaluate(payload):
    codes = []

    run_id = payload.get("runId")
    supplied_trial = payload.get("selectedTrialId")
    supplied_digest = payload.get("datasetDigest")
    metric_floor = payload.get("metricFloor")
    required_slices = payload.get("requiredSlices")
    rows = payload.get("rows")
    bytes_processed = payload.get("bytesProcessed")
    max_bytes = payload.get("maxBytes")

    # --------------------------------------------------------
    # Evaluation input validation
    # --------------------------------------------------------

    if (
        not isinstance(run_id, str)
        or len(run_id) == 0
        or len(run_id) > 128
    ):
        codes.append("INVALID_INPUT")

    if not bqml_safe_int(supplied_trial):
        codes.append("INVALID_INPUT")

    if (
        not isinstance(supplied_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", supplied_digest)
        is None
    ):
        codes.append("INVALID_INPUT")

    if (
        not bqml_finite_number(metric_floor)
        or metric_floor < 0
        or metric_floor > 1
    ):
        codes.append("INVALID_INPUT")

    if not isinstance(required_slices, dict):
        codes.append("INVALID_INPUT")
        required_slices = {}

    parsed_required_slices = {}

    for name, floor in required_slices.items():
        if (
            not isinstance(name, str)
            or len(name) == 0
            or not bqml_finite_number(floor)
            or floor < 0
            or floor > 1
        ):
            codes.append("INVALID_INPUT")
        else:
            parsed_required_slices[name] = float(floor)

    if not isinstance(rows, list):
        codes.append("INVALID_INPUT")
        rows = []

    if not bqml_safe_int(bytes_processed):
        codes.append("INVALID_INPUT")

    if not bqml_safe_int(max_bytes):
        codes.append("INVALID_INPUT")

    # --------------------------------------------------------
    # Frozen lineage validation
    # --------------------------------------------------------

    stored = None

    if isinstance(run_id, str):
        with BQLM_LOCK:
            stored_record = BQLM_RUNS.get(run_id)

            if stored_record is not None:
                stored = copy.deepcopy(
                    stored_record["response"]
                )

    lineage_valid = True

    if stored is None:
        lineage_valid = False
    else:
        # Stored selection itself must have succeeded.
        if stored.get("reasonCodes") != []:
            lineage_valid = False

        if stored.get("selectedTrialId") is None:
            lineage_valid = False

        if stored.get("datasetDigest") is None:
            lineage_valid = False

        if (
            supplied_trial
            != stored.get("selectedTrialId")
        ):
            lineage_valid = False

        if (
            supplied_digest
            != stored.get("datasetDigest")
        ):
            lineage_valid = False

    if not lineage_valid:
        codes.append("INVALID_LINEAGE")

    # --------------------------------------------------------
    # Validate final-test rows
    # --------------------------------------------------------

    invalid_test_row = False
    parsed_test_rows = []

    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                invalid_test_row = True
                continue

            if set(row.keys()) != {
                "label",
                "prediction",
                "slice"
            }:
                invalid_test_row = True
                continue

            label = row.get("label")
            prediction = row.get("prediction")
            slice_name = row.get("slice")

            if (
                isinstance(label, bool)
                or not isinstance(label, int)
                or label not in {0, 1}
            ):
                invalid_test_row = True
                continue

            if (
                isinstance(prediction, bool)
                or not isinstance(prediction, int)
                or prediction not in {0, 1}
            ):
                invalid_test_row = True
                continue

            if (
                not isinstance(slice_name, str)
                or len(slice_name) == 0
            ):
                invalid_test_row = True
                continue

            parsed_test_rows.append({
                "label": label,
                "prediction": prediction,
                "slice": slice_name
            })

    if invalid_test_row:
        codes.append("INVALID_TEST_ROW")

    # --------------------------------------------------------
    # Byte gate is independent and still checked
    # --------------------------------------------------------

    if (
        bqml_safe_int(bytes_processed)
        and bqml_safe_int(max_bytes)
        and bytes_processed > max_bytes
    ):
        codes.append("BYTE_LIMIT")

    test_metric = None
    slice_checks_pass = False

    # Empty rows OR any invalid row:
    # testMetric null, skip aggregate + slice checks.
    can_score = (
        isinstance(rows, list)
        and len(rows) > 0
        and not invalid_test_row
        and "INVALID_INPUT" not in codes
    )

    if can_score:
        correct = sum(
            1
            for r in parsed_test_rows
            if r["label"] == r["prediction"]
        )

        test_metric = round(
            correct / len(parsed_test_rows),
            12
        )

        if test_metric < float(metric_floor):
            codes.append("AGGREGATE_FLOOR")

        # Required slices
        slice_checks_pass = True

        for slice_name in bqml_utf8_sorted(
            parsed_required_slices.keys()
        ):
            slice_rows = [
                r
                for r in parsed_test_rows
                if r["slice"] == slice_name
            ]

            if not slice_rows:
                codes.append(
                    f"MISSING_SLICE:{slice_name}"
                )
                slice_checks_pass = False
                continue

            slice_correct = sum(
                1
                for r in slice_rows
                if r["label"] == r["prediction"]
            )

            slice_metric = round(
                slice_correct / len(slice_rows),
                12
            )

            if (
                slice_metric
                < parsed_required_slices[slice_name]
            ):
                codes.append(
                    f"SLICE_FLOOR:{slice_name}"
                )
                slice_checks_pass = False

    # criticalSlicePass is false for invalid input, lineage,
    # bad rows, missing slice, or failed slice floor.
    critical_slice_pass = (
        can_score
        and lineage_valid
        and slice_checks_pass
    )

    codes = bqml_sorted_codes(codes)

    decision = (
        "admit"
        if (
            len(codes) == 0
            and test_metric is not None
        )
        else "reject"
    )

    return {
        "runId": run_id,
        "selectedTrialId": supplied_trial,
        "datasetDigest": supplied_digest,
        "testMetric": test_metric,
        "criticalSlicePass": critical_slice_pass,
        "decision": decision,
        "bytesProcessed": bytes_processed,
        "reasonCodes": codes
    }


@app.post("/bqml")
def bqml(payload: Any = Body(...)):

    if not isinstance(payload, dict):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    phase = payload.get("phase")

    if phase not in {"select", "evaluate"}:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":
        run_id = payload.get("runId")

        # We need a stable fingerprint of the complete
        # selection input for replay/conflict detection.
        fingerprint = bqml_input_fingerprint(payload)

        if isinstance(run_id, str):
            with BQLM_LOCK:
                existing = BQLM_RUNS.get(run_id)

                if existing is not None:
                    if existing["fingerprint"] == fingerprint:
                        return copy.deepcopy(
                            existing["response"]
                        )

                    return JSONResponse(
                        status_code=409,
                        content={
                            "error": "RUN_ID_CONFLICT"
                        }
                    )

        response = bqml_select(payload)

        # Persist all selections under a syntactically usable run ID,
        # including failed selections, so reuse remains deterministic.
        if (
            isinstance(run_id, str)
            and len(run_id) > 0
            and len(run_id) <= 128
        ):
            with BQLM_LOCK:
                # Race-safe second check.
                existing = BQLM_RUNS.get(run_id)

                if existing is not None:
                    if (
                        existing["fingerprint"]
                        == fingerprint
                    ):
                        return copy.deepcopy(
                            existing["response"]
                        )

                    return JSONResponse(
                        status_code=409,
                        content={
                            "error": "RUN_ID_CONFLICT"
                        }
                    )

                BQLM_RUNS[run_id] = {
                    "fingerprint": fingerprint,
                    "response": copy.deepcopy(response)
                }

        return response

    # ========================================================
    # EVALUATE
    # ========================================================

    return bqml_evaluate(payload)
