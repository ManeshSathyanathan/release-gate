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
