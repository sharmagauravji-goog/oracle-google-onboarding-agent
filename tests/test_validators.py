"""Unit tests for ODB@GCP network, CIDR, naming, region/zone catalogs, and state validators."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent.state import (
    CicdProvider,
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
    SUPPORTED_EXADATA_SHAPES,
    SUPPORTED_GI_VERSIONS_DEDICATED,
    SUPPORTED_GI_VERSIONS_EXASCALE,
    get_oracle_zones_for_region,
    get_region_display_name,
    validate_cidr_block,
    validate_cost_center,
    validate_gcp_project_id,
    validate_gcp_resource_id,
    validate_gcs_bucket_name,
    validate_hostname_prefix,
    validate_non_overlapping_cidrs,
    validate_oracle_db_name,
    validate_oracle_zone,
    validate_ssh_public_key,
)


class TestRegionAndHardwareCatalogs:
    """Verify official ODB@GCP region/zone mappings and Exadata/GI catalogs."""

    def test_all_catalog_regions_have_valid_oracle_zones(self) -> None:
        # Official https://docs.cloud.google.com/oracle/database/docs/regions-and-zones has 16 regions
        assert len(ODB_REGION_CATALOG) == 16
        expected_regions = {
            "asia-northeast1": ["asia-northeast1-a-r1"],
            "asia-northeast2": ["asia-northeast2-a-r1"],
            "australia-southeast1": ["australia-southeast1-b-r1"],
            "australia-southeast2": ["australia-southeast2-a-r2", "australia-southeast2-b-r1"],
            "asia-south1": ["asia-south1-b-r1"],
            "asia-south2": ["asia-south2-b-r1"],
            "northamerica-northeast1": ["northamerica-northeast1-a-r1"],
            "northamerica-northeast2": ["northamerica-northeast2-a-r2"],
            "us-central1": ["us-central1-a-r1"],
            "us-east4": ["us-east4-a-r2", "us-east4-b-r1"],
            "us-west3": ["us-west3-a-r1"],
            "southamerica-east1": ["southamerica-east1-a-r1"],
            "europe-west2": ["europe-west2-a-r1", "europe-west2-c-r2"],
            "europe-west3": ["europe-west3-a-r2", "europe-west3-b-r1"],
            "europe-west8": ["europe-west8-b-r1", "europe-west8-a-r1"],
            "europe-west12": ["europe-west12-a-r1"],
        }
        assert set(ODB_REGION_CATALOG.keys()) == set(expected_regions.keys())
        for region, expected_zones in expected_regions.items():
            display = get_region_display_name(region)
            assert region in display
            zones = get_oracle_zones_for_region(region)
            assert zones == expected_zones
            for z in zones:
                assert validate_oracle_zone(z, region) == z

    def test_unsupported_region_or_zone_rejected(self) -> None:
        # us-east1 is not an official ODB@GCP region
        with pytest.raises(ValueError, match="Unsupported Oracle Database@Google Cloud region"):
            get_oracle_zones_for_region("us-east1")
        # us-central1 only has us-central1-a-r1, not us-central1-b-r1
        with pytest.raises(ValueError, match="not a supported Oracle zone in region"):
            validate_oracle_zone("us-central1-b-r1", "us-central1")

    def test_exadata_and_gi_catalogs_populated(self) -> None:
        assert "Exadata.X11M" in SUPPORTED_EXADATA_SHAPES
        assert "Exadata.X9M" in SUPPORTED_EXADATA_SHAPES
        assert "23.0.0.0" in SUPPORTED_GI_VERSIONS_DEDICATED
        assert "19.0.0.0" in SUPPORTED_GI_VERSIONS_DEDICATED
        assert "23.0.0.0" in SUPPORTED_GI_VERSIONS_EXASCALE
        assert "VM.Standard.E5.Flex" in SUPPORTED_BASEDB_SHAPES


class TestCidrValidators:
    """Verify CIDR block size constraints (/28 minimum block) and overlap checks."""

    def test_valid_cidr_blocks(self) -> None:
        assert validate_cidr_block("10.10.1.0/24", "client_subnet") == "10.10.1.0/24"
        assert validate_cidr_block("10.10.2.0/28", "client_subnet") == "10.10.2.0/28"
        # Host bits set should be normalized to canonical network address
        assert validate_cidr_block("10.10.1.55/24", "client_subnet") == "10.10.1.0/24"

    @pytest.mark.parametrize("invalid_cidr", ["10.10.1.0/29", "10.10.1.0/30", "10.10.1.0/32"])
    def test_cidr_smaller_than_slash_28_rejected(self, invalid_cidr: str) -> None:
        with pytest.raises(ValueError, match="minimum subnet size is /28"):
            validate_cidr_block(invalid_cidr, "client_subnet", min_prefix=16, max_prefix=28)

    def test_cidr_larger_than_min_prefix_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be between /16 and /28"):
            validate_cidr_block("10.0.0.0/12", "client_subnet", min_prefix=16, max_prefix=28)

    def test_ipv6_cidr_rejected(self) -> None:
        with pytest.raises(ValueError, match="IPv4"):
            validate_cidr_block("2001:db8::/64", "client_subnet")

    def test_non_overlapping_cidrs_pass(self) -> None:
        validate_non_overlapping_cidrs(
            {
                "VPC CIDR": "10.0.0.0/16",
                "CLIENT_SUBNET CIDR": "10.10.1.0/24",
                "BACKUP_SUBNET CIDR": "10.10.2.0/24",
            }
        )

    def test_overlapping_vpc_and_client_subnet_rejected(self) -> None:
        with pytest.raises(ValueError, match="CIDR overlap detected"):
            validate_non_overlapping_cidrs(
                {
                    "VPC CIDR": "10.0.0.0/16",
                    "CLIENT_SUBNET CIDR": "10.0.5.0/24",
                }
            )

    def test_overlapping_client_and_backup_subnet_rejected(self) -> None:
        with pytest.raises(ValueError, match="CIDR overlap detected"):
            validate_non_overlapping_cidrs(
                {
                    "VPC CIDR": "10.0.0.0/16",
                    "CLIENT_SUBNET CIDR": "192.168.10.0/24",
                    "BACKUP_SUBNET CIDR": "192.168.10.128/25",
                }
            )


class TestNamingValidators:
    """Verify GCP resource IDs, Oracle DB names, hostnames, and SSH keys."""

    @pytest.mark.parametrize("valid_id", ["odb-net-prod", "adb01", "a-b-c-123"])
    def test_valid_gcp_resource_id(self, valid_id: str) -> None:
        assert validate_gcp_resource_id(valid_id) == valid_id

    @pytest.mark.parametrize(
        "invalid_id",
        [
            "",
            "Uppercase-Not-Allowed",
            "1starts-with-number",
            "ends-with-hyphen-",
            "has_underscore",
            "a" * 64,
            "odb;rm -rf /",
        ],
    )
    def test_invalid_gcp_resource_id_rejected(self, invalid_id: str) -> None:
        with pytest.raises(ValueError):
            validate_gcp_resource_id(invalid_id)

    def test_valid_project_id(self) -> None:
        assert validate_gcp_project_id("my-odb-project-01") == "my-odb-project-01"

    def test_oracle_zone_must_match_region(self) -> None:
        assert validate_oracle_zone("us-east4-b-r1", "us-east4") == "us-east4-b-r1"
        with pytest.raises(ValueError, match="does not belong to target region"):
            validate_oracle_zone("europe-west1-b-r1", "us-east4")

    def test_oracle_db_name(self) -> None:
        assert validate_oracle_db_name("ORCLADB1") == "ORCLADB1"
        with pytest.raises(ValueError):
            validate_oracle_db_name("1INVALID")
        with pytest.raises(ValueError):
            validate_oracle_db_name("TOO_LONG_DB_NAME_123")

    def test_hostname_prefix(self) -> None:
        assert validate_hostname_prefix("exavmc") == "exavmc"
        with pytest.raises(ValueError):
            validate_hostname_prefix("x")

    def test_ssh_public_key(self) -> None:
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host"
        assert validate_ssh_public_key(key) == key
        with pytest.raises(ValueError):
            validate_ssh_public_key("not-an-ssh-key")

    def test_gcs_bucket_name(self) -> None:
        assert validate_gcs_bucket_name("odb-gcp-tfstate-prod") == "odb-gcp-tfstate-prod"
        with pytest.raises(ValueError):
            validate_gcs_bucket_name("Invalid_Bucket!")

    def test_cost_center_validator(self) -> None:
        assert validate_cost_center("finops-odb-001") == "finops-odb-001"
        with pytest.raises(ValueError):
            validate_cost_center("Invalid Cost Center!")


class TestOnboardingStateValidation:
    """Verify cross-phase state validation rules and change tracking."""

    def test_shared_vpc_requires_host_project_id(self) -> None:
        with pytest.raises(ValidationError, match="host_project_id is required"):
            Phase1ProjectContext(
                project_id="service-proj-01",
                use_shared_vpc=True,
                host_project_id=None,
                region="us-east4",
                gcp_oracle_zone="us-east4-b-r1",
            )

        p1 = Phase1ProjectContext(
            project_id="service-proj-01",
            use_shared_vpc=True,
            host_project_id="host-proj-01",
            region="us-east4",
            gcp_oracle_zone="us-east4-b-r1",
        )
        assert p1.effective_network_project_id == "host-proj-01"

    def test_exadata_and_exascale_require_backup_subnet(self) -> None:
        p1 = Phase1ProjectContext(project_id="odb-service-proj")
        p2_no_backup = Phase2NetworkConfig(
            vpc_network_name="odb-vpc",
            vpc_cidr_range="10.0.0.0/16",
            odb_network_id="odb-net-prod",
            client_subnet_id="odb-client-sub",
            client_subnet_cidr="10.10.1.0/24",
            backup_subnet_id=None,
            backup_subnet_cidr=None,
        )
        p4 = Phase4CicdConfig()

        for wt in (WorkloadType.EXADATA_DEDICATED, WorkloadType.EXASCALE):
            with pytest.raises(ValidationError, match="requires both backup_subnet_id and backup_subnet_cidr"):
                OnboardingState(
                    phase1=p1,
                    phase2=p2_no_backup,
                    phase3=Phase3DatabaseConfig(workload_type=wt),
                    phase4=p4,
                )

    def test_adb_and_basedb_succeed_without_backup_subnet(self) -> None:
        p1 = Phase1ProjectContext(project_id="odb-service-proj")
        p2_no_backup = Phase2NetworkConfig(
            vpc_network_name="odb-vpc",
            vpc_cidr_range="10.0.0.0/16",
            odb_network_id="odb-net-prod",
            client_subnet_id="odb-client-sub",
            client_subnet_cidr="10.10.1.0/24",
        )
        p4 = Phase4CicdConfig(cicd_provider=CicdProvider.CLOUDBUILD)

        for wt in (WorkloadType.ADB, WorkloadType.BASEDB):
            state = OnboardingState(
                phase1=p1,
                phase2=p2_no_backup,
                phase3=Phase3DatabaseConfig(workload_type=wt),
                phase4=p4,
            )
            assert state.phase3.workload_type == wt

    def test_optional_cost_center_and_data_classification(self) -> None:
        p1_defaults = Phase1ProjectContext(project_id="odb-service-proj")
        assert p1_defaults.cost_center is None
        assert p1_defaults.data_classification is None

        p1_blank = Phase1ProjectContext(
            project_id="odb-service-proj",
            cost_center="   ",
            data_classification="",  # type: ignore[arg-type]
        )
        assert p1_blank.cost_center is None
        assert p1_blank.data_classification is None

    def test_fingerprint_and_diff_from_defaults(self) -> None:
        state = OnboardingState(
            phase1=Phase1ProjectContext(
                project_id="custom-odb-proj",
                region="europe-west3",
                gcp_oracle_zone="europe-west3-a-r2",
            ),
            phase2=Phase2NetworkConfig(),
            phase3=Phase3DatabaseConfig(workload_type=WorkloadType.ADB),
            phase4=Phase4CicdConfig(),
        )
        fp = state.compute_fingerprint()
        assert len(fp) == 12
        diffs = state.diff_from_defaults()
        changed_keys = {item[0] for item in diffs}
        assert "Tab 1 (Project & Location).project_id" in changed_keys
        assert "Tab 1 (Project & Location).region" in changed_keys
        assert "Tab 1 (Project & Location).gcp_oracle_zone" in changed_keys
