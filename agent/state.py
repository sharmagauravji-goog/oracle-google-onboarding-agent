"""Pydantic v2 data models & 5-phase discovery state machine for ODB@GCP."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, List, Literal, Optional, Tuple
from pydantic import BaseModel, Field, field_validator, model_validator

from agent.validators import (
    validate_cidr_block,
    validate_cost_center,
    validate_gcp_project_id,
    validate_gcp_resource_id,
    validate_gcs_bucket_name,
    validate_hostname_prefix,
    validate_non_overlapping_cidrs,
    validate_oracle_db_name,
    validate_oracle_zone,
    validate_region,
    validate_ssh_public_key,
)


class WorkloadType(str, Enum):
    ADB = "adb"
    EXADATA_DEDICATED = "exadata_dedicated"
    EXASCALE = "exascale"
    BASEDB = "basedb"


class CicdProvider(str, Enum):
    GITHUB_ACTIONS = "github-actions"
    GITLAB_CI = "gitlab-ci"
    CLOUDBUILD = "cloudbuild"


class Phase1ProjectContext(BaseModel):
    """Phase 1: Google Cloud Project, Location & Enterprise Governance Context."""

    project_id: str = Field(..., description="Target Google Cloud Service Project ID")
    use_shared_vpc: bool = Field(
        default=False,
        description="Whether ODB Network attaches to a Shared VPC in a separate Host Project",
    )
    host_project_id: Optional[str] = Field(
        default=None,
        description="Shared VPC Host Project ID (required if use_shared_vpc is True)",
    )
    region: str = Field(default="us-east4", description="Target Google Cloud Region")
    gcp_oracle_zone: str = Field(
        default="us-east4-a-r2",
        description="Target GCP Oracle Zone (e.g., us-east4-a-r2, us-east4-b-r1)",
    )
    environment: Literal["dev", "staging", "prod"] = Field(
        default="prod", description="Deployment environment label"
    )
    cost_center: Optional[str] = Field(
        default=None,
        description="Optional Enterprise FinOps cost center label applied to all ODB resources",
    )
    data_classification: Optional[
        Literal["restricted", "confidential", "internal", "public"]
    ] = Field(
        default=None,
        description="Optional Enterprise data security classification label",
    )
    deletion_protection: bool = Field(
        default=True,
        description="Enable deletion protection and Terraform lifecycle safeguards",
    )

    @field_validator("project_id")
    @classmethod
    def _check_project_id(cls, v: str) -> str:
        return validate_gcp_project_id(v, "project_id")

    @field_validator("host_project_id")
    @classmethod
    def _check_host_project_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        return validate_gcp_project_id(v, "host_project_id")

    @field_validator("region")
    @classmethod
    def _check_region(cls, v: str) -> str:
        return validate_region(v)

    @field_validator("cost_center")
    @classmethod
    def _check_cost_center(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        return validate_cost_center(v)

    @field_validator("data_classification", mode="before")
    @classmethod
    def _check_data_classification(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip().lower()
        if not s or s.startswith("none"):
            return None
        return s

    @model_validator(mode="after")
    def _validate_zone_and_shared_vpc(self) -> "Phase1ProjectContext":
        self.gcp_oracle_zone = validate_oracle_zone(self.gcp_oracle_zone, self.region)
        if self.use_shared_vpc and not self.host_project_id:
            raise ValueError(
                "host_project_id is required when use_shared_vpc is enabled."
            )
        return self

    @property
    def effective_network_project_id(self) -> str:
        """Return the project ID that owns the VPC network."""
        if self.use_shared_vpc and self.host_project_id:
            return self.host_project_id
        return self.project_id


class Phase2NetworkConfig(BaseModel):
    """Phase 2: ODB Network & Subnet Topology."""

    vpc_network_name: str = Field(
        default="odb-prod-vpc",
        description="Existing or target Google Cloud VPC Network name",
    )
    vpc_cidr_range: str = Field(
        default="10.0.0.0/16",
        description="Primary CIDR block of the Google Cloud VPC (used to verify non-overlap)",
    )
    odb_network_id: str = Field(
        default="odb-net-prod",
        description="ODB Network resource identifier (1-63 lowercase alphanumeric/hyphens)",
    )
    odb_network_display_name: str = Field(
        default="odb-net-prod",
        description="Human-readable display name for the ODB Network",
    )
    client_subnet_id: str = Field(
        default="odb-client-subnet",
        description="ODB Client Subnet resource identifier",
    )
    client_subnet_cidr: str = Field(
        default="10.10.1.0/24",
        description="CIDR block for CLIENT_SUBNET (minimum /28, non-overlapping with VPC)",
    )
    backup_subnet_id: Optional[str] = Field(
        default=None,
        description="ODB Backup Subnet resource identifier (required for Exadata/Exascale)",
    )
    backup_subnet_cidr: Optional[str] = Field(
        default=None,
        description="CIDR block for BACKUP_SUBNET (minimum /28, non-overlapping)",
    )

    @field_validator("vpc_network_name")
    @classmethod
    def _check_vpc_name(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "vpc_network_name")

    @field_validator("odb_network_id")
    @classmethod
    def _check_odb_net_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "odb_network_id")

    @field_validator("client_subnet_id")
    @classmethod
    def _check_client_subnet_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "client_subnet_id")

    @field_validator("backup_subnet_id")
    @classmethod
    def _check_backup_subnet_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        return validate_gcp_resource_id(v, "backup_subnet_id")

    @field_validator("vpc_cidr_range")
    @classmethod
    def _check_vpc_cidr(cls, v: str) -> str:
        return validate_cidr_block(v, "vpc_cidr_range", min_prefix=8, max_prefix=28)

    @field_validator("client_subnet_cidr")
    @classmethod
    def _check_client_cidr(cls, v: str) -> str:
        return validate_cidr_block(v, "client_subnet_cidr", min_prefix=16, max_prefix=28)

    @field_validator("backup_subnet_cidr")
    @classmethod
    def _check_backup_cidr(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        return validate_cidr_block(v, "backup_subnet_cidr", min_prefix=16, max_prefix=28)

    @model_validator(mode="after")
    def _validate_subnet_overlaps(self) -> "Phase2NetworkConfig":
        if bool(self.backup_subnet_id) != bool(self.backup_subnet_cidr):
            raise ValueError(
                "Both backup_subnet_id and backup_subnet_cidr must be provided together."
            )
        if self.backup_subnet_id and self.backup_subnet_id == self.client_subnet_id:
            raise ValueError("backup_subnet_id must be distinct from client_subnet_id.")
        validate_non_overlapping_cidrs(
            {
                "VPC CIDR": self.vpc_cidr_range,
                "CLIENT_SUBNET CIDR": self.client_subnet_cidr,
                "BACKUP_SUBNET CIDR": self.backup_subnet_cidr,
            }
        )
        return self


class AdbConfig(BaseModel):
    """Autonomous Database Serverless (ADB-S) configuration."""

    instance_id: str = Field(default="adb-prod-01", description="ADB-S resource ID")
    display_name: str = Field(default="adb-prod-01", description="Display name")
    db_name: str = Field(default="ORCLADB", description="Oracle Database Name (1-14 chars)")
    db_workload: Literal["OLTP", "DW", "APEX", "AJD"] = Field(
        default="OLTP", description="Autonomous Database workload type"
    )
    db_version: Literal["23ai", "19c"] = Field(
        default="23ai", description="Oracle Database version"
    )
    compute_count: int = Field(default=4, ge=2, le=512, description="ECPU count")
    data_storage_size_tb: int = Field(
        default=1, ge=1, le=384, description="Data storage size in TB"
    )
    is_auto_scaling_enabled: bool = Field(
        default=True, description="Enable CPU auto-scaling"
    )
    license_type: Literal["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"] = Field(
        default="LICENSE_INCLUDED", description="Oracle license model"
    )
    mtls_connection_required: bool = Field(
        default=True, description="Require mutual TLS (mTLS) connections"
    )
    backup_retention_period_days: int = Field(
        default=30, ge=1, le=60, description="Automated backup retention period in days (1-60)"
    )
    is_local_data_guard_enabled: bool = Field(
        default=True, description="Enable Autonomous Data Guard for high availability"
    )
    character_set: str = Field(
        default="AL32UTF8", description="Database character set"
    )
    ncharacter_set: Literal["AL16UTF16", "UTF8"] = Field(
        default="AL16UTF16", description="National character set"
    )
    maintenance_schedule_type: Literal["REGULAR", "EARLY"] = Field(
        default="REGULAR", description="Autonomous maintenance schedule type"
    )

    @field_validator("instance_id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "adb.instance_id")

    @field_validator("db_name")
    @classmethod
    def _check_db_name(cls, v: str) -> str:
        return validate_oracle_db_name(v)


class ExadataDedicatedConfig(BaseModel):
    """Exadata Database Service on Dedicated Infrastructure configuration."""

    exadata_infra_id: str = Field(
        default="exa-infra-prod", description="Cloud Exadata Infrastructure ID"
    )
    exadata_display_name: str = Field(
        default="exa-infra-prod", description="Exadata Infrastructure display name"
    )
    shape: str = Field(
        default="Exadata.X11M",
        description="Exadata hardware shape (Exadata.X11M, Exadata.X9M, Exadata.X8M)",
    )
    compute_count: int = Field(
        default=2, ge=2, le=32, description="Number of database compute servers"
    )
    storage_count: int = Field(
        default=3, ge=3, le=64, description="Number of Exadata storage servers"
    )
    vm_cluster_id: str = Field(
        default="exa-vmcluster-prod", description="Cloud VM Cluster resource ID"
    )
    vm_cluster_display_name: str = Field(
        default="exa-vmcluster-prod", description="Cloud VM Cluster display name"
    )
    cpu_core_count: int = Field(
        default=8, ge=4, le=400, description="Enabled OCPU/ECPU core count across cluster"
    )
    memory_size_gb: int = Field(
        default=60, ge=30, le=6000, description="Memory allocated to VM cluster in GB"
    )
    data_storage_size_tb: float = Field(
        default=2.0, ge=2.0, le=1024.0, description="Usable ASM data storage in TB"
    )
    db_node_storage_size_gb: int = Field(
        default=120, ge=120, le=4000, description="Local DB node storage in GB"
    )
    gi_version: str = Field(
        default="23.0.0.0", description="Oracle Grid Infrastructure version"
    )
    hostname_prefix: str = Field(
        default="exavmc", description="VM cluster hostname prefix (2-13 chars)"
    )
    ssh_public_keys: List[str] = Field(
        default_factory=lambda: [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp"
        ],
        min_length=1,
        description="SSH public keys for VM cluster access",
    )
    license_type: Literal["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"] = Field(
        default="BRING_YOUR_OWN_LICENSE", description="Oracle license model"
    )
    is_sparse_diskgroup_enabled: bool = Field(
        default=False, description="Allocate ASM sparse disk group for database clones/snapshots"
    )
    is_local_backup_enabled: bool = Field(
        default=False, description="Enable local Exadata storage backups"
    )
    diagnostics_data_collection: bool = Field(
        default=True, description="Enable Oracle diagnostics, health monitoring, and incident logs"
    )
    time_zone: str = Field(
        default="UTC", description="Cluster operating system time zone"
    )
    maintenance_window_preference: Literal["CUSTOM_PREFERENCE", "NO_PREFERENCE"] = Field(
        default="CUSTOM_PREFERENCE",
        description="Exadata quarterly infrastructure maintenance window preference",
    )

    @field_validator("exadata_infra_id")
    @classmethod
    def _check_infra_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "exadata_infra_id")

    @field_validator("vm_cluster_id")
    @classmethod
    def _check_vmc_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "vm_cluster_id")

    @field_validator("hostname_prefix")
    @classmethod
    def _check_hostname(cls, v: str) -> str:
        return validate_hostname_prefix(v)

    @field_validator("ssh_public_keys")
    @classmethod
    def _check_ssh_keys(cls, keys: List[str]) -> List[str]:
        if not keys:
            raise ValueError("At least one SSH public key is required.")
        return [validate_ssh_public_key(k) for k in keys]


class ExascaleConfig(BaseModel):
    """Exadata Database Service on Exascale Infrastructure configuration."""

    vault_id: str = Field(
        default="exascale-vault-prod", description="Exascale DB Storage Vault ID"
    )
    vault_display_name: str = Field(
        default="exascale-vault-prod", description="Exascale Storage Vault display name"
    )
    high_capacity_database_storage_gb: int = Field(
        default=300, ge=300, le=100000, description="Total high-capacity storage in GB"
    )
    additional_flash_cache_percent: int = Field(
        default=20, ge=0, le=100, description="Smart flash cache percentage (0-100)"
    )
    vm_cluster_id: str = Field(
        default="exadb-vmc-prod", description="Exascale VM Cluster resource ID"
    )
    vm_cluster_display_name: str = Field(
        default="exadb-vmc-prod", description="Exascale VM Cluster display name"
    )
    shape_attribute: Literal["SMART_STORAGE", "BLOCK_STORAGE"] = Field(
        default="SMART_STORAGE", description="Exascale VM cluster shape attribute"
    )
    node_count: int = Field(default=2, ge=2, le=32, description="Number of VM nodes")
    enabled_ecpu_count_per_node: int = Field(
        default=8, ge=8, le=256, description="Enabled ECPUs per VM node (multiple of 4)"
    )
    vm_file_system_storage_size_gb: int = Field(
        default=200, ge=120, le=10000, description="Filesystem storage size per VM in GB"
    )
    gi_version: str = Field(
        default="23.0.0.0", description="Oracle Grid Infrastructure version (23ai required)"
    )
    hostname_prefix: str = Field(
        default="exascl", description="Hostname prefix (2-13 chars)"
    )
    ssh_public_keys: List[str] = Field(
        default_factory=lambda: [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp"
        ],
        min_length=1,
    )
    license_type: Literal["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"] = Field(
        default="LICENSE_INCLUDED", description="Oracle license model"
    )
    diagnostics_data_collection: bool = Field(
        default=True, description="Enable Oracle diagnostics, health monitoring, and incident logs"
    )
    time_zone: str = Field(
        default="UTC", description="Exascale VM cluster time zone"
    )

    @field_validator("vault_id")
    @classmethod
    def _check_vault_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "vault_id")

    @field_validator("vm_cluster_id")
    @classmethod
    def _check_vmc_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "vm_cluster_id")

    @field_validator("hostname_prefix")
    @classmethod
    def _check_hostname(cls, v: str) -> str:
        return validate_hostname_prefix(v)

    @field_validator("ssh_public_keys")
    @classmethod
    def _check_ssh_keys(cls, keys: List[str]) -> List[str]:
        if not keys:
            raise ValueError("At least one SSH public key is required.")
        return [validate_ssh_public_key(k) for k in keys]


class BaseDbConfig(BaseModel):
    """Oracle Base Database Service (DB System) configuration."""

    db_system_id: str = Field(
        default="basedb-prod-01", description="DB System resource ID"
    )
    display_name: str = Field(
        default="basedb-prod-01", description="DB System display name"
    )
    shape: str = Field(
        default="VM.Standard.E4.Flex",
        description="Compute shape (e.g., VM.Standard.E5.Flex, VM.Standard.E4.Flex, VM.Standard3.Flex)",
    )
    database_edition: Literal[
        "STANDARD_EDITION",
        "ENTERPRISE_EDITION",
        "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
        "ENTERPRISE_EDITION_EXTREME_PERFORMANCE",
    ] = Field(default="ENTERPRISE_EDITION", description="Oracle Database Edition")
    storage_management: Literal["ASM", "LVM"] = Field(
        default="ASM", description="Storage management software (ASM or LVM)"
    )
    initial_data_storage_size_gb: int = Field(
        default=256, ge=256, le=40960, description="Initial data storage size in GB"
    )
    data_storage_percentage: int = Field(
        default=80, ge=40, le=80, description="Storage percentage allocated to DATA vs RECO"
    )
    cpu_core_count: int = Field(
        default=4, ge=2, le=128, description="OCPU/ECPU core count"
    )
    node_count: int = Field(default=1, ge=1, le=2, description="Node count (1 or 2)")
    db_version: str = Field(
        default="23ai", description="Oracle Database version (19c or 23ai)"
    )
    db_name: str = Field(
        default="ORCLBASE", description="Initial database name (1-8 chars recommended)"
    )
    character_set: str = Field(
        default="AL32UTF8", description="Database character set"
    )
    time_zone: str = Field(
        default="UTC", description="DB System OS time zone"
    )
    hostname_prefix: str = Field(
        default="basedb", description="Hostname prefix (2-13 chars)"
    )
    ssh_public_keys: List[str] = Field(
        default_factory=lambda: [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp"
        ],
        min_length=1,
    )
    license_type: Literal["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"] = Field(
        default="LICENSE_INCLUDED", description="Oracle license model"
    )

    @field_validator("db_system_id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "db_system_id")

    @field_validator("db_name")
    @classmethod
    def _check_db_name(cls, v: str) -> str:
        return validate_oracle_db_name(v)

    @field_validator("hostname_prefix")
    @classmethod
    def _check_hostname(cls, v: str) -> str:
        return validate_hostname_prefix(v)

    @field_validator("ssh_public_keys")
    @classmethod
    def _check_ssh_keys(cls, keys: List[str]) -> List[str]:
        if not keys:
            raise ValueError("At least one SSH public key is required.")
        return [validate_ssh_public_key(k) for k in keys]


class Phase3DatabaseConfig(BaseModel):
    """Phase 3: Database Engine Specification."""

    workload_type: WorkloadType = Field(
        default=WorkloadType.ADB,
        description="Selected Oracle Database@Google Cloud service type",
    )
    adb: Optional[AdbConfig] = Field(default=None)
    exadata_dedicated: Optional[ExadataDedicatedConfig] = Field(default=None)
    exascale: Optional[ExascaleConfig] = Field(default=None)
    basedb: Optional[BaseDbConfig] = Field(default=None)

    @model_validator(mode="after")
    def _ensure_selected_workload_config(self) -> "Phase3DatabaseConfig":
        if self.workload_type == WorkloadType.ADB and self.adb is None:
            self.adb = AdbConfig()
        elif (
            self.workload_type == WorkloadType.EXADATA_DEDICATED
            and self.exadata_dedicated is None
        ):
            self.exadata_dedicated = ExadataDedicatedConfig()
        elif self.workload_type == WorkloadType.EXASCALE and self.exascale is None:
            self.exascale = ExascaleConfig()
        elif self.workload_type == WorkloadType.BASEDB and self.basedb is None:
            self.basedb = BaseDbConfig()
        return self


class Phase4CicdConfig(BaseModel):
    """Phase 4: CI/CD, Secret Manager & Terraform Backend Preferences."""

    cicd_provider: CicdProvider = Field(
        default=CicdProvider.GITHUB_ACTIONS,
        description="Target CI/CD pipeline provider",
    )
    gcs_state_bucket: str = Field(
        default="odb-gcp-tfstate-prod",
        description="GCS bucket name for remote Terraform state",
    )
    gcs_state_prefix: str = Field(
        default="odb-gcp/terraform/state",
        description="GCS state object prefix",
    )
    terraform_service_account: str = Field(
        default="tf-odb-deployer@example-project.iam.gserviceaccount.com",
        description="Google Cloud Service Account used by CI/CD pipeline",
    )
    workload_identity_provider: str = Field(
        default="projects/123456789012/locations/global/workloadIdentityPools/ci-pool/providers/ci-provider",
        description="Workload Identity Federation provider resource path for keyless CI/CD auth",
    )
    enable_secret_manager: bool = Field(
        default=True,
        description="Include Google Cloud Secret Manager integration for database admin credentials",
    )
    secret_manager_secret_id: str = Field(
        default="odb-admin-password",
        description="Google Cloud Secret Manager Secret ID for DB admin password",
    )

    @field_validator("gcs_state_bucket")
    @classmethod
    def _check_bucket(cls, v: str) -> str:
        return validate_gcs_bucket_name(v)

    @field_validator("secret_manager_secret_id")
    @classmethod
    def _check_secret_id(cls, v: str) -> str:
        return validate_gcp_resource_id(v, "secret_manager_secret_id")


class OnboardingState(BaseModel):
    """Complete 5-phase discovery state machine for ODB@GCP."""

    current_phase: int = Field(default=1, ge=1, le=5)
    phase1: Phase1ProjectContext
    phase2: Phase2NetworkConfig
    phase3: Phase3DatabaseConfig
    phase4: Phase4CicdConfig

    @model_validator(mode="after")
    def _validate_cross_phase_requirements(self) -> "OnboardingState":
        requires_backup_subnet = self.phase3.workload_type in {
            WorkloadType.EXADATA_DEDICATED,
            WorkloadType.EXASCALE,
        }
        if requires_backup_subnet and (
            not self.phase2.backup_subnet_id or not self.phase2.backup_subnet_cidr
        ):
            raise ValueError(
                f"Workload type '{self.phase3.workload_type.value}' requires both "
                "backup_subnet_id and backup_subnet_cidr in Phase 2 Network Topology."
            )
        return self

    def compute_fingerprint(self) -> str:
        """Compute a deterministic 12-character SHA-256 fingerprint of the active configuration."""
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]

    def diff_from_defaults(self) -> List[Tuple[str, str, str]]:
        """Compare the current state against default baseline values across all phases.

        Returns a list of (Tab/Parameter Label, Default Value, Captured Value) tuples
        for all customized settings.
        """
        requires_backup = self.phase3.workload_type in {
            WorkloadType.EXADATA_DEDICATED,
            WorkloadType.EXASCALE,
        }
        default_state = OnboardingState(
            phase1=Phase1ProjectContext(project_id="odb-service-prod-01"),
            phase2=Phase2NetworkConfig(
                backup_subnet_id="odb-backup-subnet" if requires_backup else None,
                backup_subnet_cidr="10.10.2.0/24" if requires_backup else None,
            ),
            phase3=Phase3DatabaseConfig(workload_type=WorkloadType.ADB),
            phase4=Phase4CicdConfig(
                gcs_state_prefix="odb-gcp/prod",
                terraform_service_account="tf-odb-deployer@odb-service-prod-01.iam.gserviceaccount.com",
            ),
        )

        diffs: List[Tuple[str, str, str]] = []

        def _compare_dict(
            prefix: str, d_base: dict[str, Any], d_curr: dict[str, Any]
        ) -> None:
            for key, curr_val in d_curr.items():
                base_val = d_base.get(key)
                label = f"{prefix}.{key}"
                if isinstance(curr_val, dict) and isinstance(base_val, dict):
                    _compare_dict(label, base_val, curr_val)
                elif curr_val != base_val:
                    diffs.append((label, str(base_val), str(curr_val)))

        _compare_dict("Tab 1 (Project & Location)", default_state.phase1.model_dump(), self.phase1.model_dump())
        _compare_dict("Tab 2 (Network Topology)", default_state.phase2.model_dump(), self.phase2.model_dump())

        if self.phase3.workload_type != default_state.phase3.workload_type:
            diffs.append(
                (
                    "Tab 3 (Database Engine).workload_type",
                    default_state.phase3.workload_type.value,
                    self.phase3.workload_type.value,
                )
            )
        wt_key = self.phase3.workload_type.value
        curr_wt_model = getattr(self.phase3, wt_key)
        base_wt_model = Phase3DatabaseConfig(workload_type=self.phase3.workload_type)
        default_wt_obj = getattr(base_wt_model, wt_key)
        if curr_wt_model and default_wt_obj:
            _compare_dict(
                f"Tab 3 ({wt_key})",
                default_wt_obj.model_dump(),
                curr_wt_model.model_dump(),
            )

        _compare_dict("Tab 4 (CI/CD & State)", default_state.phase4.model_dump(), self.phase4.model_dump())
        return diffs

    def to_summary_markdown(self) -> str:
        """Render a clean Markdown summary of all 5 discovery phases."""
        lines = [
            "# Oracle Database@Google Cloud Configuration Summary",
            "",
            "## Phase 1: Project, Location & Enterprise Governance",
            f"- **Service Project ID**: `{self.phase1.project_id}`",
            f"- **Shared VPC Mode**: `{self.phase1.use_shared_vpc}`",
        ]
        if self.phase1.use_shared_vpc:
            lines.append(f"- **Host Project ID**: `{self.phase1.host_project_id}`")
        lines.extend(
            [
                f"- **Target Region**: `{self.phase1.region}`",
                f"- **GCP Oracle Zone**: `{self.phase1.gcp_oracle_zone}`",
                f"- **Environment**: `{self.phase1.environment}`",
                f"- **FinOps Cost Center**: `{self.phase1.cost_center or 'None (Optional)'}` | **Data Classification**: `{self.phase1.data_classification or 'None (Optional)'}`",
                f"- **Deletion Protection**: `{self.phase1.deletion_protection}`",
                "",
                "## Phase 2: ODB Network Topology",
                f"- **VPC Network**: `{self.phase2.vpc_network_name}` (`{self.phase2.vpc_cidr_range}`)",
                f"- **ODB Network ID**: `{self.phase2.odb_network_id}` (`{self.phase2.odb_network_display_name}`)",
                f"- **Client Subnet**: `{self.phase2.client_subnet_id}` (`{self.phase2.client_subnet_cidr}`)",
            ]
        )
        if self.phase2.backup_subnet_id and self.phase2.backup_subnet_cidr:
            lines.append(
                f"- **Backup Subnet**: `{self.phase2.backup_subnet_id}` (`{self.phase2.backup_subnet_cidr}`)"
            )

        lines.extend(
            [
                "",
                f"## Phase 3: Database Engine (`{self.phase3.workload_type.value}`)",
            ]
        )
        if self.phase3.workload_type == WorkloadType.ADB and self.phase3.adb:
            adb = self.phase3.adb
            lines.extend(
                [
                    f"- **ADB-S Instance ID**: `{adb.instance_id}` (DB: `{adb.db_name}`)",
                    f"- **Workload / Version**: `{adb.db_workload}` / `{adb.db_version}` (`{adb.character_set}`)",
                    f"- **Compute / Storage**: `{adb.compute_count} ECPUs` / `{adb.data_storage_size_tb} TB` (Autoscale: `{adb.is_auto_scaling_enabled}`)",
                    f"- **HA & Backup**: Local Data Guard `{adb.is_local_data_guard_enabled}` | Retention `{adb.backup_retention_period_days} days` | Maintenance `{adb.maintenance_schedule_type}`",
                    f"- **License Model**: `{adb.license_type}` | **mTLS Required**: `{adb.mtls_connection_required}`",
                ]
            )
        elif (
            self.phase3.workload_type == WorkloadType.EXADATA_DEDICATED
            and self.phase3.exadata_dedicated
        ):
            exa = self.phase3.exadata_dedicated
            lines.extend(
                [
                    f"- **Exadata Infrastructure**: `{exa.exadata_infra_id}` (`{exa.shape}`, `{exa.compute_count}` compute / `{exa.storage_count}` storage)",
                    f"- **Cloud VM Cluster**: `{exa.vm_cluster_id}` (`{exa.cpu_core_count}` cores, `{exa.memory_size_gb}` GB RAM, `{exa.data_storage_size_tb}` TB ASM)",
                    f"- **GI Version / License**: `{exa.gi_version}` / `{exa.license_type}` (Timezone: `{exa.time_zone}`)",
                    f"- **Enterprise Options**: Diagnostics `{exa.diagnostics_data_collection}` | Sparse Diskgroup `{exa.is_sparse_diskgroup_enabled}` | Maintenance `{exa.maintenance_window_preference}`",
                ]
            )
        elif self.phase3.workload_type == WorkloadType.EXASCALE and self.phase3.exascale:
            exs = self.phase3.exascale
            lines.extend(
                [
                    f"- **Exascale Storage Vault**: `{exs.vault_id}` (`{exs.high_capacity_database_storage_gb}` GB, `{exs.additional_flash_cache_percent}%` Flash Cache)",
                    f"- **Exascale VM Cluster**: `{exs.vm_cluster_id}` (`{exs.node_count}` nodes, `{exs.enabled_ecpu_count_per_node}` ECPUs/node)",
                    f"- **GI Version / Shape Attribute**: `{exs.gi_version}` / `{exs.shape_attribute}` (Timezone: `{exs.time_zone}`)",
                    f"- **License / Diagnostics**: `{exs.license_type}` | Diagnostics `{exs.diagnostics_data_collection}`",
                ]
            )
        elif self.phase3.workload_type == WorkloadType.BASEDB and self.phase3.basedb:
            bdb = self.phase3.basedb
            lines.extend(
                [
                    f"- **DB System ID**: `{bdb.db_system_id}` (DB: `{bdb.db_name}`, Version: `{bdb.db_version}`, Charset: `{bdb.character_set}`)",
                    f"- **Shape / Edition**: `{bdb.shape}` (`{bdb.cpu_core_count}` cores, `{bdb.node_count}` node) / `{bdb.database_edition}`",
                    f"- **Storage Management**: `{bdb.storage_management}` (`{bdb.initial_data_storage_size_gb}` GB, `{bdb.data_storage_percentage}%` DATA)",
                ]
            )

        lines.extend(
            [
                "",
                "## Phase 4: CI/CD, Secret Manager & Remote State",
                f"- **CI/CD Provider**: `{self.phase4.cicd_provider.value}`",
                f"- **GCS State Bucket**: `gs://{self.phase4.gcs_state_bucket}/{self.phase4.gcs_state_prefix}`",
                f"- **Deployer Service Account**: `{self.phase4.terraform_service_account}`",
                f"- **Secret Manager Integration**: `{self.phase4.enable_secret_manager}` (`{self.phase4.secret_manager_secret_id}`)",
            ]
        )
        return "\n".join(lines)
