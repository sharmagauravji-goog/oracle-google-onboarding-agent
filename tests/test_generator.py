"""Unit tests for Jinja2 Terraform & CI/CD template rendering and safe directory export."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent.generator import InfrastructureGenerator
from agent.state import (
    CicdProvider,
    OnboardingState,
    Phase1ProjectContext,
    Phase2NetworkConfig,
    Phase3DatabaseConfig,
    Phase4CicdConfig,
    WorkloadType,
)


def _build_state(
    workload_type: WorkloadType,
    cicd_provider: CicdProvider = CicdProvider.GITHUB_ACTIONS,
    use_shared_vpc: bool = False,
) -> OnboardingState:
    requires_backup = workload_type in {
        WorkloadType.EXADATA_DEDICATED,
        WorkloadType.EXASCALE,
    }
    return OnboardingState(
        phase1=Phase1ProjectContext(
            project_id="odb-service-prod-01",
            use_shared_vpc=use_shared_vpc,
            host_project_id="odb-host-net-01" if use_shared_vpc else None,
            region="us-east4",
            gcp_oracle_zone="us-east4-b-r1",
            environment="prod",
            cost_center="finops-odb-001",
            data_classification="restricted",
            deletion_protection=True,
        ),
        phase2=Phase2NetworkConfig(
            vpc_network_name="odb-shared-vpc" if use_shared_vpc else "odb-standalone-vpc",
            vpc_cidr_range="10.0.0.0/16",
            odb_network_id="odb-net-prod",
            odb_network_display_name="odb-net-prod",
            client_subnet_id="odb-client-subnet",
            client_subnet_cidr="10.10.1.0/24",
            backup_subnet_id="odb-backup-subnet" if requires_backup else None,
            backup_subnet_cidr="10.10.2.0/24" if requires_backup else None,
        ),
        phase3=Phase3DatabaseConfig(workload_type=workload_type),
        phase4=Phase4CicdConfig(
            cicd_provider=cicd_provider,
            gcs_state_bucket="odb-gcp-tfstate-prod",
            gcs_state_prefix="odb-gcp/prod",
            terraform_service_account="tf-deployer@odb-service-prod-01.iam.gserviceaccount.com",
            enable_secret_manager=True,
            secret_manager_secret_id="odb-admin-password",
        ),
    )


class TestInfrastructureGenerator:
    """Test HCL and CI/CD rendering across all 4 ODB workloads and 3 CI/CD providers."""

    @pytest.mark.parametrize(
        "workload_type,expected_module_file,expected_resource_type",
        [
            (
                WorkloadType.ADB,
                "modules/adb/main.tf",
                "google_oracle_database_autonomous_database",
            ),
            (
                WorkloadType.EXADATA_DEDICATED,
                "modules/exadata_dedicated/main.tf",
                "google_oracle_database_cloud_exadata_infrastructure",
            ),
            (
                WorkloadType.EXASCALE,
                "modules/exascale/main.tf",
                "google_oracle_database_exascale_db_storage_vault",
            ),
            (
                WorkloadType.BASEDB,
                "modules/basedb/main.tf",
                "google_oracle_database_db_system",
            ),
        ],
    )
    def test_render_all_workloads(
        self,
        workload_type: WorkloadType,
        expected_module_file: str,
        expected_resource_type: str,
    ) -> None:
        gen = InfrastructureGenerator()
        state = _build_state(workload_type=workload_type)
        bundle = gen.render_bundle(state)

        # Verify root files exist
        for root_file in ("versions.tf", "main.tf", "variables.tf", "terraform.tfvars", "outputs.tf"):
            assert root_file in bundle
            assert len(bundle[root_file].strip()) > 0

        # Verify provider >= 7.0.0 and GCS backend
        assert 'version = ">= 7.0.0"' in bundle["versions.tf"]
        assert 'bucket = "odb-gcp-tfstate-prod"' in bundle["versions.tf"]

        # Verify Terraform 1.5+ check block and enterprise governance labels
        assert 'check "odb_region_zone_alignment"' in bundle["main.tf"]
        assert 'cost_center              = "finops-odb-001"' in bundle["terraform.tfvars"]
        assert 'data_classification      = "restricted"' in bundle["terraform.tfvars"]

        # Verify networking module
        assert "google_oracle_database_odb_network" in bundle["modules/networking/main.tf"]
        assert "google_oracle_database_odb_subnet" in bundle["modules/networking/main.tf"]

        # Verify selected workload module
        assert expected_module_file in bundle
        assert expected_resource_type in bundle[expected_module_file]

    def test_optional_labels_omitted_renders_null(self) -> None:
        gen = InfrastructureGenerator()
        state = _build_state(workload_type=WorkloadType.ADB)
        state.phase1.cost_center = None
        state.phase1.data_classification = None
        bundle = gen.render_bundle(state)

        assert "cost_center              = null" in bundle["terraform.tfvars"]
        assert "data_classification      = null" in bundle["terraform.tfvars"]
        assert "var.cost_center != null" in bundle["modules/adb/main.tf"]
        assert "var.data_classification != null" in bundle["modules/adb/main.tf"]

    def test_enterprise_adb_and_secret_manager_features(self) -> None:
        gen = InfrastructureGenerator()
        state = _build_state(workload_type=WorkloadType.ADB)
        bundle = gen.render_bundle(state)

        assert 'data "google_secret_manager_secret_version" "db_admin_password"' in bundle["main.tf"]
        assert "backup_retention_period_days" in bundle["modules/adb/main.tf"]
        assert "is_local_data_guard_enabled" in bundle["modules/adb/main.tf"]
        assert "deletion_protection" in bundle["modules/adb/main.tf"]

    def test_enterprise_exadata_dedicated_features(self) -> None:
        gen = InfrastructureGenerator()
        state = _build_state(workload_type=WorkloadType.EXADATA_DEDICATED)
        bundle = gen.render_bundle(state)

        assert 'exadata_shape                       = "Exadata.X11M"' in bundle["terraform.tfvars"]
        assert 'gi_version                          = "23.0.0.0"' in bundle["terraform.tfvars"]
        assert "diagnostics_data_collection_options" in bundle["modules/exadata_dedicated/main.tf"]
        assert "maintenance_window" in bundle["modules/exadata_dedicated/main.tf"]

    def test_shared_vpc_renders_host_project_id(self) -> None:
        gen = InfrastructureGenerator()
        state = _build_state(workload_type=WorkloadType.ADB, use_shared_vpc=True)
        bundle = gen.render_bundle(state)

        assert 'project_id               = "odb-service-prod-01"' in bundle["terraform.tfvars"]
        assert 'network_project_id       = "odb-host-net-01"' in bundle["terraform.tfvars"]
        assert "projects/${var.network_project_id}/global/networks/${var.vpc_network_name}" in bundle[
            "modules/networking/main.tf"
        ]

    @pytest.mark.parametrize(
        "cicd_provider,expected_pipeline_path",
        [
            (CicdProvider.GITHUB_ACTIONS, ".github/workflows/deploy-odb.yml"),
            (CicdProvider.GITLAB_CI, ".gitlab-ci.yml"),
            (CicdProvider.CLOUDBUILD, "cloudbuild.yaml"),
        ],
    )
    def test_all_cicd_pipelines_render_valid_yaml(
        self, cicd_provider: CicdProvider, expected_pipeline_path: str
    ) -> None:
        gen = InfrastructureGenerator()
        state = _build_state(workload_type=WorkloadType.EXASCALE, cicd_provider=cicd_provider)
        bundle = gen.render_bundle(state)

        assert expected_pipeline_path in bundle
        parsed_yaml = yaml.safe_load(bundle[expected_pipeline_path])
        assert isinstance(parsed_yaml, dict)

    def test_export_to_directory_writes_files_safely(self, tmp_path: Path) -> None:
        gen = InfrastructureGenerator()
        state = _build_state(workload_type=WorkloadType.EXADATA_DEDICATED)
        out_dir = gen.export_to_directory(
            state=state,
            base_output_dir=tmp_path,
            folder_name="generated-tf-test",
        )

        assert out_dir == (tmp_path / "generated-tf-test").resolve()
        assert (out_dir / "main.tf").is_file()
        assert (out_dir / "modules" / "networking" / "main.tf").is_file()
        assert (out_dir / "modules" / "exadata_dedicated" / "main.tf").is_file()
        assert (out_dir / ".github" / "workflows" / "deploy-odb.yml").is_file()
        assert (out_dir / "DEPLOYMENT_SUMMARY.md").is_file()

    def test_export_sanitizes_traversal_folder_name(self, tmp_path: Path) -> None:
        gen = InfrastructureGenerator()
        state = _build_state(workload_type=WorkloadType.ADB)
        with pytest.raises(ValueError, match="Invalid export folder name"):
            gen.export_to_directory(state=state, base_output_dir=tmp_path, folder_name="..")
