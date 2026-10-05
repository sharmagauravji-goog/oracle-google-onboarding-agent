"""Streamlit Web UI for the Oracle Database@Google Cloud Onboarding & Infrastructure Agent."""

from __future__ import annotations

import importlib
import io
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# Ensure repository root is on sys.path when invoked via `streamlit run agent/web.py`
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import streamlit as st
from pydantic import ValidationError

import agent.generator
import agent.preflight
import agent.state
import agent.validators

# Force reload of submodules on every Streamlit script rerun so updates to
# ODB_REGION_CATALOG, Pydantic models, and templates take effect immediately
# in an already-running Streamlit server process.
importlib.reload(agent.validators)
importlib.reload(agent.state)
importlib.reload(agent.preflight)
importlib.reload(agent.generator)

from agent.generator import InfrastructureGenerator
from agent.preflight import run_all_preflight_checks
from agent.state import (
    AdbConfig,
    BaseDbConfig,
    CicdProvider,
    ExadataDedicatedConfig,
    ExascaleConfig,
    OnboardingState,
    Phase1ProjectContext,
    Phase2NetworkConfig,
    Phase3DatabaseConfig,
    Phase4CicdConfig,
    WorkloadType,
)
from agent.validators import (
    ODB_REGION_CATALOG,
    SUPPORTED_BASEDB_SHAPES,
    SUPPORTED_CHARACTER_SETS,
    SUPPORTED_EXADATA_SHAPES,
    SUPPORTED_GI_VERSIONS_DEDICATED,
    SUPPORTED_GI_VERSIONS_EXASCALE,
    SUPPORTED_TIMEZONES,
    get_oracle_zones_for_region,
    get_region_display_name,
)


def _build_zip_bytes(bundle: dict[str, str]) -> bytes:
    """Package rendered files into an in-memory ZIP archive for download."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path, content in bundle.items():
            zf.writestr(rel_path, content)
    return buf.getvalue()


def main() -> None:
    st.set_page_config(
        page_title="Oracle Database@Google Cloud Onboarding Agent",
        page_icon="☁️",
        layout="wide",
    )

    st.title("Oracle Database@Google Cloud — Onboarding & Infrastructure Agent")
    st.caption(
        "Interactive 5-Phase Discovery • Strict CIDR & Naming Validation • "
        "HashiCorp Google Provider >= 7.0 • Enterprise Modular Terraform & CI/CD Generator"
    )

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "1️⃣ Phase 1: Project & Location",
            "2️⃣ Phase 2: Network Topology",
            "3️⃣ Phase 3: Database Workload",
            "4️⃣ Phase 4: CI/CD & State",
            "5️⃣ Phase 5: Preview & Export",
        ]
    )

    # -------------------------------------------------------------------------
    # Tab 1: Project, Location & Enterprise Governance Context
    # -------------------------------------------------------------------------
    with tab1:
        st.subheader("Phase 1: Google Cloud Project, Region & Enterprise Governance")
        col1, col2 = st.columns(2)
        with col1:
            project_id = st.text_input(
                "Service Project ID",
                value="odb-service-prod-01",
                help="Google Cloud Project ID where Oracle Database@Google Cloud resources will be provisioned.",
            )
            use_shared_vpc = st.checkbox(
                "Use Shared VPC (Host Project + Service Project separation)",
                value=False,
            )
            host_project_id = (
                st.text_input("Shared VPC Host Project ID", value="odb-host-net-prod")
                if use_shared_vpc
                else None
            )
            environment = st.selectbox(
                "Deployment Environment",
                options=["prod", "staging", "dev"],
                index=0,
            )

        with col2:
            sorted_regions = sorted(ODB_REGION_CATALOG.keys())
            default_region_idx = (
                sorted_regions.index("us-east4")
                if "us-east4" in sorted_regions
                else 0
            )
            region = st.selectbox(
                "Target Google Cloud Region (16 Official ODB@GCP Regions)",
                options=sorted_regions,
                index=default_region_idx,
                format_func=get_region_display_name,
                key="odb_region_official_v2",
                help="Official Google Cloud regions where Oracle Database@Google Cloud is available (https://docs.cloud.google.com/oracle/database/docs/regions-and-zones).",
            )
            available_oracle_zones = get_oracle_zones_for_region(region)
            gcp_oracle_zone = st.selectbox(
                f"Available GCP Oracle Zone in {region} ({len(available_oracle_zones)} available)",
                options=available_oracle_zones,
                index=0,
                key=f"odb_zone_official_v2_{region}",
                help="Select the regional GCP Oracle Zone hosting your dedicated ODB hardware/service.",
            )
            st.caption(
                f"Supported Oracle Zone(s) in `{region}`: "
                + ", ".join(f"`{z}`" for z in available_oracle_zones)
            )

        st.markdown("#### Enterprise Governance & FinOps Guardrails")
        g1, g2, g3 = st.columns(3)
        with g1:
            raw_cost_center = st.text_input(
                "FinOps Cost Center Label (Optional)",
                value="",
                placeholder="e.g., finops-odb-001 (leave blank to omit)",
                help="Optional `cost_center` label applied across all provisioned ODB networks, subnets, and databases.",
            )
            cost_center = raw_cost_center.strip() or None
        with g2:
            raw_data_class = st.selectbox(
                "Data Classification Label (Optional)",
                options=[
                    "None (Omit Label)",
                    "restricted",
                    "confidential",
                    "internal",
                    "public",
                ],
                index=0,
                help="Optional `data_classification` governance label.",
            )
            data_classification = (
                None if raw_data_class.startswith("None") else raw_data_class
            )
        with g3:
            deletion_protection = st.checkbox(
                "Enable Database Deletion Protection",
                value=True,
                help="Prevents accidental database destruction in Terraform (`deletion_protection = true`).",
            )

        st.divider()
        pf_col1, pf_col2 = st.columns([1, 1])
        with pf_col1:
            run_live_pf = st.button("🔍 Run Live GCP Pre-Flight Check (gcloud)")
        with pf_col2:
            run_dry_pf = st.button("🧪 Run Simulated Pre-Flight Check (Dry-Run)")

        if run_live_pf or run_dry_pf:
            results = run_all_preflight_checks(
                project_id,
                region,
                host_project_id=host_project_id,
                dry_run=run_dry_pf,
            )
            for res in results:
                if res.passed:
                    st.success(f"**{res.check_name}**: {res.detail}")
                else:
                    st.warning(
                        f"**{res.check_name}**: {res.detail} "
                        f"(Remediation: `{res.remediation or 'N/A'}`)"
                    )

    # -------------------------------------------------------------------------
    # Tab 3: Database Workload (Evaluated before Tab 2 so Backup Subnet auto-toggles)
    # -------------------------------------------------------------------------
    with tab3:
        st.subheader("Phase 3: Oracle Database Engine & Enterprise Specification")
        workload_label_map = {
            WorkloadType.ADB: "Autonomous Database Serverless (ADB-S)",
            WorkloadType.EXADATA_DEDICATED: "Exadata Database Service on Dedicated Infrastructure",
            WorkloadType.EXASCALE: "Exadata Database Service on Exascale Infrastructure",
            WorkloadType.BASEDB: "Base Database Service (VM DB System)",
        }
        selected_workload = st.radio(
            "Select Oracle Database Workload",
            options=list(WorkloadType),
            format_func=lambda w: workload_label_map[w],
            horizontal=True,
        )

        adb_cfg = None
        exa_cfg = None
        exs_cfg = None
        bdb_cfg = None

        if selected_workload == WorkloadType.ADB:
            c1, c2 = st.columns(2)
            with c1:
                adb_id = st.text_input("ADB-S Instance ID", value="adb-prod-01")
                adb_display = st.text_input("Display Name", value="adb-prod-01")
                adb_db_name = st.text_input("Oracle Database Name", value="ORCLADB")
                adb_workload = st.selectbox(
                    "Workload Profile",
                    options=["OLTP", "DW", "APEX", "AJD"],
                    index=0,
                )
                adb_version = st.selectbox(
                    "Oracle Database Version", options=["23ai", "19c"], index=0
                )
                adb_charset = st.selectbox(
                    "Character Set", options=SUPPORTED_CHARACTER_SETS, index=0
                )
                adb_ncharset = st.selectbox(
                    "National Character Set", options=["AL16UTF16", "UTF8"], index=0
                )
            with c2:
                adb_ecpu = st.number_input(
                    "ECPU Count", min_value=2, max_value=512, value=4, step=2
                )
                adb_storage_tb = st.number_input(
                    "Data Storage (TB)", min_value=1, max_value=384, value=1
                )
                adb_backup_days = st.slider(
                    "Automated Backup Retention Period (Days)",
                    min_value=1,
                    max_value=60,
                    value=30,
                )
                adb_license = st.selectbox(
                    "License Model",
                    options=["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"],
                    index=0,
                )
                adb_maint_type = st.selectbox(
                    "Maintenance Schedule Type",
                    options=["REGULAR", "EARLY"],
                    index=0,
                )
                adb_autoscale = st.checkbox("Enable CPU Auto-Scaling (Up to 3x ECPUs)", value=True)
                adb_mtls = st.checkbox("Require Mutual TLS (mTLS) Connections", value=True)
                adb_dataguard = st.checkbox(
                    "Enable Autonomous Data Guard (High Availability Standby)",
                    value=True,
                )

        elif selected_workload == WorkloadType.EXADATA_DEDICATED:
            c1, c2 = st.columns(2)
            with c1:
                exa_infra_id = st.text_input(
                    "Cloud Exadata Infrastructure ID", value="exa-infra-prod"
                )
                exa_shape_options = list(SUPPORTED_EXADATA_SHAPES.keys())
                exa_shape = st.selectbox(
                    "Exadata Hardware Shape",
                    options=exa_shape_options,
                    index=0,
                    format_func=lambda s: SUPPORTED_EXADATA_SHAPES.get(s, s),
                    help="Select the physical Exadata rack/server generation.",
                )
                exa_compute = st.number_input(
                    "Database Compute Server Count", min_value=2, max_value=32, value=2
                )
                exa_storage = st.number_input(
                    "Exadata Storage Server Count", min_value=3, max_value=64, value=3
                )
                exa_maint_pref = st.selectbox(
                    "Infrastructure Maintenance Preference",
                    options=["CUSTOM_PREFERENCE", "NO_PREFERENCE"],
                    index=0,
                )
                exa_vmc_id = st.text_input(
                    "Cloud VM Cluster ID", value="exa-vmcluster-prod"
                )
                exa_host_prefix = st.text_input("Hostname Prefix (2-13 chars)", value="exavmc")
            with c2:
                gi_options = list(SUPPORTED_GI_VERSIONS_DEDICATED.keys())
                exa_gi = st.selectbox(
                    "Oracle Grid Infrastructure (GI) Version",
                    options=gi_options,
                    index=0,
                    format_func=lambda g: SUPPORTED_GI_VERSIONS_DEDICATED.get(g, g),
                    help="Supported Oracle Grid Infrastructure release for the Cloud VM Cluster.",
                )
                exa_cores = st.number_input(
                    "Enabled CPU Cores", min_value=4, max_value=400, value=8, step=2
                )
                exa_mem_gb = st.number_input(
                    "VM Cluster Memory Size (GB)", min_value=30, max_value=6000, value=60
                )
                exa_asm_tb = st.number_input(
                    "Usable ASM Data Storage (TB)",
                    min_value=2.0,
                    max_value=1024.0,
                    value=2.0,
                    step=1.0,
                )
                exa_node_gb = st.number_input(
                    "Local DB Node Storage (GB)", min_value=120, max_value=4000, value=120
                )
                exa_tz = st.selectbox(
                    "Cluster OS Time Zone", options=SUPPORTED_TIMEZONES, index=0
                )
                exa_license = st.selectbox(
                    "License Model",
                    options=["BRING_YOUR_OWN_LICENSE", "LICENSE_INCLUDED"],
                    index=0,
                )
                exa_diag = st.checkbox(
                    "Enable Oracle Diagnostics, Health Monitoring & Incident Logs",
                    value=True,
                )
                exa_sparse = st.checkbox(
                    "Enable ASM Sparse Diskgroup (Snapshots & Thin Clones)",
                    value=False,
                )
                exa_local_bkp = st.checkbox(
                    "Enable Local Exadata Storage Backups",
                    value=False,
                )
            exa_ssh = st.text_area(
                "SSH Public Key(s) (One OpenSSH key per line)",
                value="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp",
            )

        elif selected_workload == WorkloadType.EXASCALE:
            c1, c2 = st.columns(2)
            with c1:
                exs_vault_id = st.text_input(
                    "Exascale Storage Vault ID", value="exascale-vault-prod"
                )
                exs_storage_gb = st.number_input(
                    "High-Capacity Database Storage (GB)",
                    min_value=300,
                    max_value=100000,
                    value=300,
                    step=100,
                )
                exs_flash_pct = st.slider(
                    "Additional Smart Flash Cache (%)", min_value=0, max_value=100, value=20
                )
                exs_vmc_id = st.text_input(
                    "Exascale VM Cluster ID", value="exadb-vmc-prod"
                )
                exs_shape_attr = st.selectbox(
                    "Exascale Shape Attribute",
                    options=["SMART_STORAGE", "BLOCK_STORAGE"],
                    index=0,
                )
                exs_host_prefix = st.text_input("Hostname Prefix", value="exascl")
            with c2:
                exs_gi_options = list(SUPPORTED_GI_VERSIONS_EXASCALE.keys())
                exs_gi = st.selectbox(
                    "Oracle Grid Infrastructure (GI) Version (23ai)",
                    options=exs_gi_options,
                    index=0,
                    format_func=lambda g: SUPPORTED_GI_VERSIONS_EXASCALE.get(g, g),
                )
                exs_nodes = st.number_input(
                    "VM Node Count", min_value=2, max_value=32, value=2
                )
                exs_ecpu = st.number_input(
                    "Enabled ECPUs per Node (Multiple of 4)",
                    min_value=8,
                    max_value=256,
                    value=8,
                    step=4,
                )
                exs_fs_gb = st.number_input(
                    "VM Filesystem Storage per Node (GB)",
                    min_value=120,
                    max_value=10000,
                    value=200,
                )
                exs_tz = st.selectbox(
                    "Cluster Time Zone", options=SUPPORTED_TIMEZONES, index=0
                )
                exs_license = st.selectbox(
                    "License Model",
                    options=["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"],
                    index=0,
                )
                exs_diag = st.checkbox(
                    "Enable Oracle Diagnostics, Health Monitoring & Incident Logs",
                    value=True,
                )
            exs_ssh = st.text_area(
                "SSH Public Key(s) (One OpenSSH key per line)",
                value="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp",
            )

        else:
            c1, c2 = st.columns(2)
            with c1:
                bdb_id = st.text_input("DB System ID", value="basedb-prod-01")
                bdb_shape_options = list(SUPPORTED_BASEDB_SHAPES.keys())
                bdb_shape = st.selectbox(
                    "Compute Hardware Shape",
                    options=bdb_shape_options,
                    index=1,  # VM.Standard.E4.Flex default
                    format_func=lambda s: SUPPORTED_BASEDB_SHAPES.get(s, s),
                )
                bdb_edition = st.selectbox(
                    "Oracle Database Edition",
                    options=[
                        "ENTERPRISE_EDITION",
                        "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "ENTERPRISE_EDITION_EXTREME_PERFORMANCE",
                        "STANDARD_EDITION",
                    ],
                    index=0,
                )
                bdb_storage_mgmt = st.selectbox(
                    "Storage Management Software", options=["ASM", "LVM"], index=0
                )
                bdb_storage_gb = st.number_input(
                    "Initial Data Storage (GB)",
                    min_value=256,
                    max_value=40960,
                    value=256,
                    step=128,
                )
                bdb_storage_pct = st.slider(
                    "DATA Storage Percentage (vs RECO)",
                    min_value=40,
                    max_value=80,
                    value=80,
                    step=10,
                )
            with c2:
                bdb_cores = st.number_input(
                    "Enabled CPU Core Count", min_value=2, max_value=128, value=4, step=2
                )
                bdb_nodes = st.selectbox("Node Count (1 = Single Instance, 2 = RAC)", options=[1, 2], index=0)
                bdb_version = st.selectbox(
                    "Oracle Database Version", options=["23ai", "19c"], index=0
                )
                bdb_db_name = st.text_input("Initial Database Name (1-8 chars)", value="ORCLBASE")
                bdb_charset = st.selectbox(
                    "Character Set", options=SUPPORTED_CHARACTER_SETS, index=0
                )
                bdb_tz = st.selectbox(
                    "OS Time Zone", options=SUPPORTED_TIMEZONES, index=0
                )
                bdb_host_prefix = st.text_input("Hostname Prefix", value="basedb")
                bdb_license = st.selectbox(
                    "License Model",
                    options=["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"],
                    index=0,
                )
            bdb_ssh = st.text_area(
                "SSH Public Key(s) (One OpenSSH key per line)",
                value="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp",
            )

    # -------------------------------------------------------------------------
    # Tab 2: Network Topology
    # -------------------------------------------------------------------------
    requires_backup = selected_workload in {
        WorkloadType.EXADATA_DEDICATED,
        WorkloadType.EXASCALE,
    }
    with tab2:
        st.subheader("Phase 2: ODB Network & Subnet Topology")
        st.info(
            "💡 **ODB Subnet Rules**: `CLIENT_SUBNET` and `BACKUP_SUBNET` must be `/28` or larger "
            "(`/16` to `/28`) and **must not overlap** with your Google Cloud VPC CIDR or each other."
        )
        n1, n2 = st.columns(2)
        with n1:
            vpc_network_name = st.text_input(
                "Google Cloud VPC Network Name", value="odb-prod-vpc"
            )
            vpc_cidr_range = st.text_input(
                "VPC Primary CIDR (Verified Non-Overlapping)", value="10.0.0.0/16"
            )
            odb_network_id = st.text_input("ODB Network ID", value="odb-net-prod")
            odb_network_display_name = st.text_input(
                "ODB Network Display Name", value="odb-net-prod"
            )
        with n2:
            client_subnet_id = st.text_input(
                "Client Subnet ID (CLIENT_SUBNET)", value="odb-client-subnet"
            )
            client_subnet_cidr = st.text_input(
                "Client Subnet CIDR (minimum /28)", value="10.10.1.0/24"
            )
            enable_backup = st.checkbox(
                "Include ODB Backup Subnet (BACKUP_SUBNET — Mandatory for Exadata/Exascale)",
                value=requires_backup,
                disabled=requires_backup,
            )
            if enable_backup or requires_backup:
                backup_subnet_id = st.text_input(
                    "Backup Subnet ID (BACKUP_SUBNET)", value="odb-backup-subnet"
                )
                backup_subnet_cidr = st.text_input(
                    "Backup Subnet CIDR (minimum /28)", value="10.10.2.0/24"
                )
            else:
                backup_subnet_id = None
                backup_subnet_cidr = None

    # -------------------------------------------------------------------------
    # Tab 4: CI/CD, Secret Manager & Pipeline Preferences
    # -------------------------------------------------------------------------
    with tab4:
        st.subheader("Phase 4: CI/CD Pipeline, Secret Manager & Terraform State")
        p4_col1, p4_col2 = st.columns(2)
        with p4_col1:
            cicd_choice = st.selectbox(
                "Target CI/CD System",
                options=[c.value for c in CicdProvider],
                index=0,
            )
            gcs_state_bucket = st.text_input(
                "GCS Remote State Bucket Name", value="odb-gcp-tfstate-prod"
            )
            gcs_state_prefix = st.text_input(
                "GCS State Object Prefix", value=f"odb-gcp/{environment}"
            )
        with p4_col2:
            terraform_sa = st.text_input(
                "Terraform Deployer Service Account",
                value=f"tf-odb-deployer@{project_id}.iam.gserviceaccount.com",
            )
            wif_provider = st.text_input(
                "Workload Identity Federation Provider Resource",
                value="projects/123456789012/locations/global/workloadIdentityPools/ci-pool/providers/ci-provider",
            )
            enable_secret_manager = st.checkbox(
                "Include Google Cloud Secret Manager Lookup for DB Admin Password",
                value=True,
                help="Generates a `data.google_secret_manager_secret_version` block in Terraform for zero-secret `.tfvars` deployments.",
            )
            secret_manager_secret_id = st.text_input(
                "Secret Manager Secret ID",
                value="odb-admin-password",
                disabled=not enable_secret_manager,
            )

    # -------------------------------------------------------------------------
    # Tab 5: Live Capture Banner, Diff Tracker, Code Preview, & Export
    # -------------------------------------------------------------------------
    with tab5:
        st.subheader("Phase 5: Live Configuration Capture, Code Preview & Export")
        try:
            p1 = Phase1ProjectContext(
                project_id=project_id,
                use_shared_vpc=use_shared_vpc,
                host_project_id=host_project_id,
                region=region,
                gcp_oracle_zone=gcp_oracle_zone,
                environment=environment,  # type: ignore[arg-type]
                cost_center=cost_center,
                data_classification=data_classification,  # type: ignore[arg-type]
                deletion_protection=deletion_protection,
            )
            p2 = Phase2NetworkConfig(
                vpc_network_name=vpc_network_name,
                vpc_cidr_range=vpc_cidr_range,
                odb_network_id=odb_network_id,
                odb_network_display_name=odb_network_display_name,
                client_subnet_id=client_subnet_id,
                client_subnet_cidr=client_subnet_cidr,
                backup_subnet_id=backup_subnet_id,
                backup_subnet_cidr=backup_subnet_cidr,
            )
            if selected_workload == WorkloadType.ADB:
                adb_cfg = AdbConfig(
                    instance_id=adb_id,
                    display_name=adb_display,
                    db_name=adb_db_name,
                    db_workload=adb_workload,  # type: ignore[arg-type]
                    db_version=adb_version,  # type: ignore[arg-type]
                    compute_count=int(adb_ecpu),
                    data_storage_size_tb=int(adb_storage_tb),
                    is_auto_scaling_enabled=adb_autoscale,
                    license_type=adb_license,  # type: ignore[arg-type]
                    mtls_connection_required=adb_mtls,
                    backup_retention_period_days=int(adb_backup_days),
                    is_local_data_guard_enabled=adb_dataguard,
                    character_set=adb_charset,
                    ncharacter_set=adb_ncharset,  # type: ignore[arg-type]
                    maintenance_schedule_type=adb_maint_type,  # type: ignore[arg-type]
                )
            elif selected_workload == WorkloadType.EXADATA_DEDICATED:
                exa_cfg = ExadataDedicatedConfig(
                    exadata_infra_id=exa_infra_id,
                    exadata_display_name=exa_infra_id,
                    shape=exa_shape,
                    compute_count=int(exa_compute),
                    storage_count=int(exa_storage),
                    vm_cluster_id=exa_vmc_id,
                    vm_cluster_display_name=exa_vmc_id,
                    cpu_core_count=int(exa_cores),
                    memory_size_gb=int(exa_mem_gb),
                    data_storage_size_tb=float(exa_asm_tb),
                    db_node_storage_size_gb=int(exa_node_gb),
                    gi_version=exa_gi,
                    hostname_prefix=exa_host_prefix,
                    ssh_public_keys=[
                        k.strip() for k in exa_ssh.splitlines() if k.strip()
                    ],
                    license_type=exa_license,  # type: ignore[arg-type]
                    is_sparse_diskgroup_enabled=exa_sparse,
                    is_local_backup_enabled=exa_local_bkp,
                    diagnostics_data_collection=exa_diag,
                    time_zone=exa_tz,
                    maintenance_window_preference=exa_maint_pref,  # type: ignore[arg-type]
                )
            elif selected_workload == WorkloadType.EXASCALE:
                exs_cfg = ExascaleConfig(
                    vault_id=exs_vault_id,
                    vault_display_name=exs_vault_id,
                    high_capacity_database_storage_gb=int(exs_storage_gb),
                    additional_flash_cache_percent=int(exs_flash_pct),
                    vm_cluster_id=exs_vmc_id,
                    vm_cluster_display_name=exs_vmc_id,
                    shape_attribute=exs_shape_attr,  # type: ignore[arg-type]
                    node_count=int(exs_nodes),
                    enabled_ecpu_count_per_node=int(exs_ecpu),
                    vm_file_system_storage_size_gb=int(exs_fs_gb),
                    gi_version=exs_gi,
                    hostname_prefix=exs_host_prefix,
                    ssh_public_keys=[
                        k.strip() for k in exs_ssh.splitlines() if k.strip()
                    ],
                    license_type=exs_license,  # type: ignore[arg-type]
                    diagnostics_data_collection=exs_diag,
                    time_zone=exs_tz,
                )
            else:
                bdb_cfg = BaseDbConfig(
                    db_system_id=bdb_id,
                    display_name=bdb_id,
                    shape=bdb_shape,
                    database_edition=bdb_edition,  # type: ignore[arg-type]
                    storage_management=bdb_storage_mgmt,  # type: ignore[arg-type]
                    initial_data_storage_size_gb=int(bdb_storage_gb),
                    data_storage_percentage=int(bdb_storage_pct),
                    cpu_core_count=int(bdb_cores),
                    node_count=int(bdb_nodes),
                    db_version=bdb_version,
                    db_name=bdb_db_name,
                    character_set=bdb_charset,
                    time_zone=bdb_tz,
                    hostname_prefix=bdb_host_prefix,
                    ssh_public_keys=[
                        k.strip() for k in bdb_ssh.splitlines() if k.strip()
                    ],
                    license_type=bdb_license,  # type: ignore[arg-type]
                )

            p3 = Phase3DatabaseConfig(
                workload_type=selected_workload,
                adb=adb_cfg,
                exadata_dedicated=exa_cfg,
                exascale=exs_cfg,
                basedb=bdb_cfg,
            )
            p4 = Phase4CicdConfig(
                cicd_provider=CicdProvider(cicd_choice),
                gcs_state_bucket=gcs_state_bucket,
                gcs_state_prefix=gcs_state_prefix,
                terraform_service_account=terraform_sa,
                workload_identity_provider=wif_provider,
                enable_secret_manager=enable_secret_manager,
                secret_manager_secret_id=secret_manager_secret_id,
            )
            state = OnboardingState(
                current_phase=5, phase1=p1, phase2=p2, phase3=p3, phase4=p4
            )

            generator = InfrastructureGenerator()
            bundle = generator.render_bundle(state)
            fingerprint = state.compute_fingerprint()
            diffs = state.diff_from_defaults()
            sync_time = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

            # Live Synchronization & Readiness Banner
            st.success(
                f"✅ **All Changes Captured & Validated ({sync_time})** — "
                f"Your selections from **Tabs 1–4** are actively synchronized (Revision `#{fingerprint}`). "
                "Your enterprise Terraform & CI/CD bundle is ready to download below."
            )

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Bundle Readiness", "READY TO DOWNLOAD")
            m2.metric(
                "Captured Customizations",
                f"{len(diffs)} Modified" if diffs else "Default Baseline",
            )
            m3.metric("Config Revision Hash", f"#{fingerprint}")
            m4.metric("Generated Artifacts", f"{len(bundle)} Files")

            with st.expander(
                f"📋 View Captured Changes from Tabs 1–4 ({len(diffs)} customized parameter(s))",
                expanded=bool(diffs),
            ):
                if diffs:
                    st.markdown(
                        "The table below confirms every parameter you modified across Tabs 1–4 that has been baked into the generated Terraform files:"
                    )
                    diff_rows = [
                        {
                            "Tab & Setting": param,
                            "Default Baseline": default_val,
                            "Captured Value (Active in Terraform)": current_val,
                        }
                        for param, default_val, current_val in diffs
                    ]
                    st.table(diff_rows)
                else:
                    st.info(
                        "Currently using the default baseline configuration across Tabs 1–4. "
                        "Any changes you make in Tabs 1, 2, 3, or 4 will immediately appear here and update the Terraform bundle."
                    )

            col_dl, col_exp = st.columns(2)
            with col_dl:
                st.download_button(
                    label=f"⬇️ Download Terraform + CI/CD Bundle (.zip) [Rev #{fingerprint}]",
                    data=_build_zip_bytes(bundle),
                    file_name=f"odb-gcp-{selected_workload.value}-{environment}-{fingerprint}.zip",
                    mime="application/zip",
                    type="primary",
                    use_container_width=True,
                )
            with col_exp:
                if st.button(
                    "💾 Export Bundle to Local ./generated-tf-<timestamp>/",
                    use_container_width=True,
                ):
                    export_dir = generator.export_to_directory(
                        state, base_output_dir=Path(".")
                    )
                    st.info(f"Exported {len(bundle)} files to `{export_dir}`")

            with st.expander("📄 View Full Architecture & Governance Summary", expanded=False):
                st.markdown(state.to_summary_markdown())

            st.divider()
            selected_file = st.selectbox(
                "Inspect Generated Terraform / CI/CD File",
                options=sorted(bundle.keys()),
            )
            if selected_file:
                lang = (
                    "hcl"
                    if selected_file.endswith((".tf", ".tfvars"))
                    else "yaml"
                    if selected_file.endswith((".yml", ".yaml"))
                    else "markdown"
                )
                st.code(bundle[selected_file], language=lang)

        except ValidationError as exc:
            st.error(
                "⚠️ **Action Required — Configuration Validation Error in Tabs 1–4**\n\n"
                "Please resolve the following validation issue(s) to unlock Terraform bundle download:\n\n"
                f"```text\n{exc}\n```"
            )
        except ValueError as exc:
            st.error(f"⚠️ **Validation Error**: {exc}")


if __name__ == "__main__":
    main()
