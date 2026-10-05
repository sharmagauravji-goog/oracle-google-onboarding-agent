"""Pre-flight verification for Google Cloud APIs, ODB Entitlements, and IAM roles."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from agent.validators import validate_gcp_project_id, validate_region

REQUIRED_GCP_APIS = (
    "oracledatabase.googleapis.com",
    "compute.googleapis.com",
    "servicenetworking.googleapis.com",
)

REQUIRED_IAM_ROLES = (
    "roles/oracledatabase.admin",
    "roles/compute.networkAdmin",
    "roles/servicenetworking.networksAdmin",
)

ALLOWED_GCLOUD_DIRS = (
    "/usr/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/google/cloud-sdk/bin",
)


@dataclass(frozen=True)
class PreflightResult:
    """Result of an individual pre-flight check."""

    check_name: str
    passed: bool
    detail: str
    remediation: Optional[str] = None


def _resolve_gcloud_binary() -> Optional[str]:
    """Safely resolve the gcloud binary path."""
    gcloud_path = shutil.which("gcloud")
    if not gcloud_path:
        return None
    resolved = os.path.realpath(gcloud_path)
    if not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
        return None
    return resolved


def check_enabled_apis(project_id: str) -> List[PreflightResult]:
    """Check whether required Google Cloud APIs are enabled on the target project."""
    clean_project = validate_gcp_project_id(project_id)
    gcloud_bin = _resolve_gcloud_binary()
    if not gcloud_bin:
        return [
            PreflightResult(
                check_name="Google Cloud SDK (gcloud)",
                passed=False,
                detail="gcloud CLI not found on PATH.",
                remediation="Install Google Cloud SDK and run 'gcloud auth login'.",
            )
        ]

    try:
        proc = subprocess.run(
            [
                gcloud_bin,
                "services",
                "list",
                "--enabled",
                f"--project={clean_project}",
                "--format=value(config.name)",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.SubprocessError as exc:
        return [
            PreflightResult(
                check_name="GCP API Enablement Query",
                passed=False,
                detail=f"Failed to query enabled services: {exc}",
                remediation=f"Verify access to project '{clean_project}'.",
            )
        ]

    if proc.returncode != 0:
        return [
            PreflightResult(
                check_name="GCP API Enablement Query",
                passed=False,
                detail="Unable to list enabled GCP APIs (check authentication or project permissions).",
                remediation=(
                    f"gcloud services enable {' '.join(REQUIRED_GCP_APIS)} "
                    f"--project={clean_project}"
                ),
            )
        ]

    enabled = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    results: List[PreflightResult] = []
    for api in REQUIRED_GCP_APIS:
        is_enabled = api in enabled
        results.append(
            PreflightResult(
                check_name=f"API: {api}",
                passed=is_enabled,
                detail="Enabled" if is_enabled else "Not enabled",
                remediation=(
                    None
                    if is_enabled
                    else f"gcloud services enable {api} --project={clean_project}"
                ),
            )
        )
    return results


def check_odb_entitlement(project_id: str, region: str) -> PreflightResult:
    """Check whether the project has an active Oracle Database@Google Cloud entitlement."""
    clean_project = validate_gcp_project_id(project_id)
    clean_region = validate_region(region)
    gcloud_bin = _resolve_gcloud_binary()
    if not gcloud_bin:
        return PreflightResult(
            check_name="ODB@GCP Marketplace Entitlement",
            passed=False,
            detail="gcloud CLI unavailable.",
            remediation="Install Google Cloud SDK.",
        )

    try:
        proc = subprocess.run(
            [
                gcloud_bin,
                "oracle-database",
                "entitlements",
                "list",
                f"--location={clean_region}",
                f"--project={clean_project}",
                "--format=json",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.SubprocessError as exc:
        return PreflightResult(
            check_name="ODB@GCP Marketplace Entitlement",
            passed=False,
            detail=f"Entitlement check timed out or errored: {exc}",
            remediation="Verify network connectivity and Marketplace subscription.",
        )

    if proc.returncode != 0:
        return PreflightResult(
            check_name="ODB@GCP Marketplace Entitlement",
            passed=False,
            detail="Could not query ODB@GCP entitlements.",
            remediation=(
                f"gcloud oracle-database entitlements list --location={clean_region} "
                f"--project={clean_project}"
            ),
        )

    try:
        entitlements = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        entitlements = []

    if not entitlements:
        return PreflightResult(
            check_name="ODB@GCP Marketplace Entitlement",
            passed=False,
            detail=f"No active ODB@GCP entitlement found in {clean_project} ({clean_region}).",
            remediation=(
                "Subscribe to Oracle Database@Google Cloud in Google Cloud Marketplace "
                "and link your OCI tenancy."
            ),
        )

    states = [str(item.get("state", "UNKNOWN")) for item in entitlements]
    passed = any(s.upper() == "ACTIVE" for s in states)
    return PreflightResult(
        check_name="ODB@GCP Marketplace Entitlement",
        passed=passed,
        detail=f"Entitlement states: {', '.join(states)}",
        remediation=(
            None
            if passed
            else "Ensure the ODB@GCP Marketplace entitlement state is ACTIVE."
        ),
    )


def check_iam_permissions(project_id: str) -> PreflightResult:
    """Verify whether the active gcloud identity holds required ODB@GCP IAM roles."""
    clean_project = validate_gcp_project_id(project_id)
    gcloud_bin = _resolve_gcloud_binary()
    if not gcloud_bin:
        return PreflightResult(
            check_name="IAM Role Verification",
            passed=False,
            detail="gcloud CLI unavailable.",
            remediation="Install Google Cloud SDK.",
        )

    try:
        acct_proc = subprocess.run(
            [gcloud_bin, "config", "get-value", "account"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        active_account = acct_proc.stdout.strip()
        if not active_account:
            return PreflightResult(
                check_name="IAM Role Verification",
                passed=False,
                detail="No active gcloud account configured.",
                remediation="Run 'gcloud auth login'.",
            )

        iam_proc = subprocess.run(
            [
                gcloud_bin,
                "projects",
                "get-iam-policy",
                clean_project,
                "--format=json",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.SubprocessError as exc:
        return PreflightResult(
            check_name="IAM Role Verification",
            passed=False,
            detail=f"Failed to inspect project IAM policy: {exc}",
            remediation="Verify resourcemanager.projects.getIamPolicy permission.",
        )

    if iam_proc.returncode != 0:
        return PreflightResult(
            check_name="IAM Role Verification",
            passed=False,
            detail="Unable to read project IAM policy.",
            remediation=(
                f"Ensure the caller holds {', '.join(REQUIRED_IAM_ROLES)} on {clean_project}."
            ),
        )

    try:
        policy = json.loads(iam_proc.stdout or "{}")
    except json.JSONDecodeError:
        policy = {}

    granted_roles = set()
    for binding in policy.get("bindings", []):
        members = binding.get("members", [])
        if any(active_account in m for m in members):
            granted_roles.add(binding.get("role", ""))

    if "roles/owner" in granted_roles or "roles/editor" in granted_roles:
        return PreflightResult(
            check_name="IAM Role Verification",
            passed=True,
            detail=f"Principal holds broad administrative role ({', '.join(sorted(granted_roles))}).",
        )

    missing = [r for r in REQUIRED_IAM_ROLES if r not in granted_roles]
    if not missing:
        return PreflightResult(
            check_name="IAM Role Verification",
            passed=True,
            detail="All required ODB@GCP and Network Admin IAM roles are bound.",
        )

    return PreflightResult(
        check_name="IAM Role Verification",
        passed=False,
        detail=f"Missing recommended roles: {', '.join(missing)}",
        remediation=(
            f"Grant {', '.join(missing)} to your deployment principal in project {clean_project}."
        ),
    )


def run_all_preflight_checks(
    project_id: str,
    region: str,
    host_project_id: Optional[str] = None,
    dry_run: bool = False,
) -> List[PreflightResult]:
    """Execute API, Entitlement, and IAM pre-flight checks (supports offline dry_run mode)."""
    clean_project = validate_gcp_project_id(project_id)
    clean_region = validate_region(region)
    clean_host = (
        validate_gcp_project_id(host_project_id, "host_project_id")
        if host_project_id
        else None
    )

    if dry_run:
        sim_results = [
            PreflightResult(
                check_name=f"API: {api}",
                passed=True,
                detail=f"[DRY-RUN] Verified {api} requirement on '{clean_project}'.",
            )
            for api in REQUIRED_GCP_APIS
        ]
        sim_results.append(
            PreflightResult(
                check_name="ODB@GCP Marketplace Entitlement",
                passed=True,
                detail=f"[DRY-RUN] Verified Marketplace entitlement requirement in '{clean_region}'.",
            )
        )
        sim_results.append(
            PreflightResult(
                check_name="IAM Role Verification",
                passed=True,
                detail=f"[DRY-RUN] Verified required IAM roles ({', '.join(REQUIRED_IAM_ROLES)}).",
            )
        )
        if clean_host:
            sim_results.append(
                PreflightResult(
                    check_name="Shared VPC Host Project IAM",
                    passed=True,
                    detail=f"[DRY-RUN] Verified Shared VPC host project '{clean_host}' network permissions.",
                )
            )
        return sim_results

    results: List[PreflightResult] = []
    results.extend(check_enabled_apis(clean_project))
    results.append(check_odb_entitlement(clean_project, clean_region))
    results.append(check_iam_permissions(clean_project))
    if clean_host:
        host_iam = check_iam_permissions(clean_host)
        results.append(
            PreflightResult(
                check_name=f"Shared VPC Host IAM ({clean_host})",
                passed=host_iam.passed,
                detail=host_iam.detail,
                remediation=host_iam.remediation,
            )
        )
    return results

