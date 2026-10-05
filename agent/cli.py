"""Typer + Rich interactive CLI for Oracle Database@Google Cloud Onboarding Agent."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# Ensure repository root is on sys.path when invoked directly
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.syntax import Syntax
from rich.table import Table

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
from agent.validators import ODB_REGION_CATALOG, get_oracle_zones_for_region

app = typer.Typer(
    name="odb-agent",
    help="Oracle Database@Google Cloud Onboarding & Infrastructure Agent CLI",
    add_completion=False,
)
console = Console()


def _render_preflight_table(
    project_id: str,
    region: str,
    host_project_id: Optional[str] = None,
    dry_run: bool = False,
) -> None:
    """Run and display pre-flight verification results in a Rich table."""
    console.print(
        f"\n[bold cyan]Running Google Cloud Pre-Flight Checks for '{project_id}' ({region})...[/bold cyan]"
    )
    results = run_all_preflight_checks(
        project_id, region, host_project_id=host_project_id, dry_run=dry_run
    )
    table = Table(title="ODB@GCP Pre-Flight Verification", show_lines=True)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")
    table.add_column("Remediation")

    for res in results:
        status_badge = "[green]PASS[/green]" if res.passed else "[yellow]WARN[/yellow]"
        table.add_row(
            res.check_name,
            status_badge,
            res.detail,
            res.remediation or "-",
        )
    console.print(table)


@app.command("preflight")
def preflight_cmd(
    project_id: str = typer.Option(..., "--project-id", "-p", help="Google Cloud Project ID"),
    region: str = typer.Option("us-east4", "--region", "-r", help="Google Cloud Region"),
    host_project_id: Optional[str] = typer.Option(
        None, "--host-project-id", help="Optional Shared VPC Host Project ID"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Simulate pre-flight checks offline without invoking gcloud"
    ),
) -> None:
    """Run standalone pre-flight checks for APIs, ODB Entitlements, and IAM roles."""
    _render_preflight_table(
        project_id, region, host_project_id=host_project_id, dry_run=dry_run
    )


@app.command("interview")
def interview_cmd(
    output_dir: Path = typer.Option(
        Path("."),
        "--output-dir",
        "-o",
        help="Base directory where the generated-tf-<timestamp> folder will be written",
    ),
    run_preflight: bool = typer.Option(
        False,
        "--preflight/--no-preflight",
        help="Run live gcloud API/Entitlement/IAM pre-flight checks during Phase 1",
    ),
) -> None:
    """Launch the 5-phase interactive discovery interview to generate Terraform & CI/CD."""
    console.print(
        Panel.fit(
            "[bold white]Oracle Database@Google Cloud Onboarding & Infrastructure Agent[/bold white]\n"
            "[dim]Guided 5-Phase Discovery -> Validated Terraform (google >= 7.0) + CI/CD Pipelines[/dim]",
            border_style="bright_blue",
        )
    )

    # -------------------------------------------------------------------------
    # Phase 1: Project & Location Context
    # -------------------------------------------------------------------------
    console.print("\n[bold cyan]Phase 1 of 5: Project & Location Context[/bold cyan]")
    while True:
        project_id = Prompt.ask("Google Cloud Service Project ID", default="odb-service-prod-01")
        use_shared_vpc = Confirm.ask("Attach ODB Network to a Shared VPC?", default=False)
        host_project_id: Optional[str] = None
        if use_shared_vpc:
            host_project_id = Prompt.ask("Shared VPC Host Project ID", default="odb-host-net-prod")
        region = Prompt.ask(
            "Target Google Cloud Region",
            choices=list(ODB_REGION_CATALOG.keys()),
            default="us-east4",
        )
        valid_zones = get_oracle_zones_for_region(region)
        gcp_oracle_zone = Prompt.ask(
            "Target GCP Oracle Zone",
            choices=valid_zones,
            default=valid_zones[0],
        )
        environment = Prompt.ask(
            "Environment label", choices=["dev", "staging", "prod"], default="prod"
        )
        try:
            phase1 = Phase1ProjectContext(
                project_id=project_id,
                use_shared_vpc=use_shared_vpc,
                host_project_id=host_project_id,
                region=region,
                gcp_oracle_zone=gcp_oracle_zone,
                environment=environment,  # type: ignore[arg-type]
            )
            break
        except ValidationError as err:
            console.print(f"[bold red]Validation Error:[/bold red] {err}")

    if run_preflight:
        _render_preflight_table(phase1.project_id, phase1.region)

    # -------------------------------------------------------------------------
    # Phase 3 selection up-front or in Phase 2/3 so backup subnet is prompted dynamically
    # -------------------------------------------------------------------------
    console.print("\n[bold cyan]Phase 2 of 5: Network Topology[/bold cyan]")
    workload_choice = Prompt.ask(
        "Select target Oracle Database Workload (determines whether BACKUP_SUBNET is required)",
        choices=[w.value for w in WorkloadType],
        default=WorkloadType.ADB.value,
    )
    selected_workload = WorkloadType(workload_choice)
    needs_backup_subnet = selected_workload in {
        WorkloadType.EXADATA_DEDICATED,
        WorkloadType.EXASCALE,
    }

    while True:
        vpc_network_name = Prompt.ask("Google Cloud VPC Network Name", default="odb-prod-vpc")
        vpc_cidr_range = Prompt.ask(
            "Existing VPC Primary CIDR (for non-overlap validation)",
            default="10.0.0.0/16",
        )
        odb_network_id = Prompt.ask("ODB Network ID", default="odb-net-prod")
        odb_network_display_name = Prompt.ask(
            "ODB Network Display Name", default=odb_network_id
        )
        client_subnet_id = Prompt.ask("Client Subnet ID", default="odb-client-subnet")
        client_subnet_cidr = Prompt.ask(
            "Client Subnet CIDR (minimum /28, non-overlapping with VPC)",
            default="10.10.1.0/24",
        )
        backup_subnet_id: Optional[str] = None
        backup_subnet_cidr: Optional[str] = None
        if needs_backup_subnet or Confirm.ask(
            "Configure an optional ODB Backup Subnet?", default=False
        ):
            backup_subnet_id = Prompt.ask("Backup Subnet ID", default="odb-backup-subnet")
            backup_subnet_cidr = Prompt.ask(
                "Backup Subnet CIDR (minimum /28, non-overlapping)",
                default="10.10.2.0/24",
            )
        try:
            phase2 = Phase2NetworkConfig(
                vpc_network_name=vpc_network_name,
                vpc_cidr_range=vpc_cidr_range,
                odb_network_id=odb_network_id,
                odb_network_display_name=odb_network_display_name,
                client_subnet_id=client_subnet_id,
                client_subnet_cidr=client_subnet_cidr,
                backup_subnet_id=backup_subnet_id,
                backup_subnet_cidr=backup_subnet_cidr,
            )
            break
        except ValidationError as err:
            console.print(f"[bold red]Validation Error:[/bold red] {err}")

    # -------------------------------------------------------------------------
    # Phase 3: Database Engine Specification
    # -------------------------------------------------------------------------
    console.print(
        f"\n[bold cyan]Phase 3 of 5: Database Engine Specification ({selected_workload.value})[/bold cyan]"
    )
    while True:
        try:
            if selected_workload == WorkloadType.ADB:
                adb_cfg = AdbConfig(
                    instance_id=Prompt.ask("ADB-S Instance ID", default="adb-prod-01"),
                    display_name=Prompt.ask("ADB-S Display Name", default="adb-prod-01"),
                    db_name=Prompt.ask("Oracle Database Name (1-14 chars)", default="ORCLADB"),
                    db_workload=Prompt.ask(
                        "Workload Type",
                        choices=["OLTP", "DW", "APEX", "AJD"],
                        default="OLTP",
                    ),  # type: ignore[arg-type]
                    db_version=Prompt.ask(
                        "Database Version", choices=["23ai", "19c"], default="23ai"
                    ),  # type: ignore[arg-type]
                    compute_count=IntPrompt.ask("ECPU Count (>= 2)", default=4),
                    data_storage_size_tb=IntPrompt.ask("Storage Size (TB)", default=1),
                    is_auto_scaling_enabled=Confirm.ask(
                        "Enable CPU Auto-Scaling?", default=True
                    ),
                    license_type=Prompt.ask(
                        "License Type",
                        choices=["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"],
                        default="LICENSE_INCLUDED",
                    ),  # type: ignore[arg-type]
                    mtls_connection_required=Confirm.ask(
                        "Require mTLS Connections?", default=True
                    ),
                )
                phase3 = Phase3DatabaseConfig(workload_type=selected_workload, adb=adb_cfg)
            elif selected_workload == WorkloadType.EXADATA_DEDICATED:
                exa_cfg = ExadataDedicatedConfig(
                    exadata_infra_id=Prompt.ask(
                        "Cloud Exadata Infrastructure ID", default="exa-infra-prod"
                    ),
                    exadata_display_name=Prompt.ask(
                        "Exadata Infrastructure Display Name", default="exa-infra-prod"
                    ),
                    shape=Prompt.ask("Exadata Shape", default="Exadata.X9M"),
                    compute_count=IntPrompt.ask("Compute Node Count (>= 2)", default=2),
                    storage_count=IntPrompt.ask("Storage Server Count (>= 3)", default=3),
                    vm_cluster_id=Prompt.ask(
                        "Cloud VM Cluster ID", default="exa-vmcluster-prod"
                    ),
                    vm_cluster_display_name=Prompt.ask(
                        "Cloud VM Cluster Display Name", default="exa-vmcluster-prod"
                    ),
                    cpu_core_count=IntPrompt.ask("VM Cluster CPU Core Count", default=8),
                    memory_size_gb=IntPrompt.ask("VM Cluster Memory (GB)", default=60),
                    data_storage_size_tb=float(
                        Prompt.ask("ASM Data Storage Size (TB)", default="2.0")
                    ),
                    db_node_storage_size_gb=IntPrompt.ask(
                        "DB Node Local Storage (GB)", default=120
                    ),
                    gi_version=Prompt.ask(
                        "Grid Infrastructure Version", default="19.0.0.0"
                    ),
                    hostname_prefix=Prompt.ask("Hostname Prefix", default="exavmc"),
                    ssh_public_keys=[
                        Prompt.ask(
                            "SSH Public Key",
                            default="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp",
                        )
                    ],
                    license_type=Prompt.ask(
                        "License Type",
                        choices=["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"],
                        default="BRING_YOUR_OWN_LICENSE",
                    ),  # type: ignore[arg-type]
                )
                phase3 = Phase3DatabaseConfig(
                    workload_type=selected_workload, exadata_dedicated=exa_cfg
                )
            elif selected_workload == WorkloadType.EXASCALE:
                exs_cfg = ExascaleConfig(
                    vault_id=Prompt.ask(
                        "Exascale DB Storage Vault ID", default="exascale-vault-prod"
                    ),
                    vault_display_name=Prompt.ask(
                        "Storage Vault Display Name", default="exascale-vault-prod"
                    ),
                    high_capacity_database_storage_gb=IntPrompt.ask(
                        "High Capacity Storage (GB, >= 300)", default=300
                    ),
                    additional_flash_cache_percent=IntPrompt.ask(
                        "Smart Flash Cache Percentage (0-100)", default=20
                    ),
                    vm_cluster_id=Prompt.ask(
                        "Exascale VM Cluster ID", default="exadb-vmc-prod"
                    ),
                    vm_cluster_display_name=Prompt.ask(
                        "Exascale VM Cluster Display Name", default="exadb-vmc-prod"
                    ),
                    shape_attribute=Prompt.ask(
                        "Shape Attribute",
                        choices=["SMART_STORAGE", "BLOCK_STORAGE"],
                        default="SMART_STORAGE",
                    ),  # type: ignore[arg-type]
                    node_count=IntPrompt.ask("VM Node Count (>= 2)", default=2),
                    enabled_ecpu_count_per_node=IntPrompt.ask(
                        "Enabled ECPUs per Node (>= 8)", default=8
                    ),
                    vm_file_system_storage_size_gb=IntPrompt.ask(
                        "VM Filesystem Storage (GB, >= 120)", default=200
                    ),
                    gi_version=Prompt.ask(
                        "Grid Infrastructure Version", default="23.0.0.0"
                    ),
                    hostname_prefix=Prompt.ask("Hostname Prefix", default="exascl"),
                    ssh_public_keys=[
                        Prompt.ask(
                            "SSH Public Key",
                            default="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp",
                        )
                    ],
                    license_type=Prompt.ask(
                        "License Type",
                        choices=["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"],
                        default="LICENSE_INCLUDED",
                    ),  # type: ignore[arg-type]
                )
                phase3 = Phase3DatabaseConfig(
                    workload_type=selected_workload, exascale=exs_cfg
                )
            else:
                bdb_cfg = BaseDbConfig(
                    db_system_id=Prompt.ask("DB System ID", default="basedb-prod-01"),
                    display_name=Prompt.ask(
                        "DB System Display Name", default="basedb-prod-01"
                    ),
                    shape=Prompt.ask("Compute Shape", default="VM.Standard.E4.Flex"),
                    database_edition=Prompt.ask(
                        "Database Edition",
                        choices=[
                            "STANDARD_EDITION",
                            "ENTERPRISE_EDITION",
                            "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                            "ENTERPRISE_EDITION_EXTREME_PERFORMANCE",
                        ],
                        default="ENTERPRISE_EDITION",
                    ),  # type: ignore[arg-type]
                    storage_management=Prompt.ask(
                        "Storage Management", choices=["ASM", "LVM"], default="ASM"
                    ),  # type: ignore[arg-type]
                    initial_data_storage_size_gb=IntPrompt.ask(
                        "Initial Data Storage Size (GB, >= 256)", default=256
                    ),
                    cpu_core_count=IntPrompt.ask("CPU Core Count (>= 2)", default=4),
                    node_count=IntPrompt.ask("Node Count (1 or 2)", default=1),
                    db_version=Prompt.ask("Database Version", default="23ai"),
                    db_name=Prompt.ask("Initial Database Name", default="ORCLBASE"),
                    hostname_prefix=Prompt.ask("Hostname Prefix", default="basedb"),
                    ssh_public_keys=[
                        Prompt.ask(
                            "SSH Public Key",
                            default="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@odb-gcp",
                        )
                    ],
                    license_type=Prompt.ask(
                        "License Type",
                        choices=["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"],
                        default="LICENSE_INCLUDED",
                    ),  # type: ignore[arg-type]
                )
                phase3 = Phase3DatabaseConfig(
                    workload_type=selected_workload, basedb=bdb_cfg
                )
            break
        except ValidationError as err:
            console.print(f"[bold red]Validation Error:[/bold red] {err}")

    # -------------------------------------------------------------------------
    # Phase 4: CI/CD & Pipeline Preferences
    # -------------------------------------------------------------------------
    console.print("\n[bold cyan]Phase 4 of 5: CI/CD & Pipeline Preferences[/bold cyan]")
    while True:
        cicd_choice = Prompt.ask(
            "Target CI/CD System",
            choices=[c.value for c in CicdProvider],
            default=CicdProvider.GITHUB_ACTIONS.value,
        )
        gcs_state_bucket = Prompt.ask(
            "GCS Bucket for Terraform Remote State",
            default=f"{phase1.project_id}-tfstate",
        )
        gcs_state_prefix = Prompt.ask(
            "GCS State Prefix", default=f"odb-gcp/{phase1.environment}"
        )
        terraform_sa = Prompt.ask(
            "Deployer Google Service Account Email",
            default=f"tf-odb-deployer@{phase1.project_id}.iam.gserviceaccount.com",
        )
        try:
            phase4 = Phase4CicdConfig(
                cicd_provider=CicdProvider(cicd_choice),
                gcs_state_bucket=gcs_state_bucket,
                gcs_state_prefix=gcs_state_prefix,
                terraform_service_account=terraform_sa,
            )
            break
        except ValidationError as err:
            console.print(f"[bold red]Validation Error:[/bold red] {err}")

    # -------------------------------------------------------------------------
    # Phase 5: Output Generation & Review
    # -------------------------------------------------------------------------
    state = OnboardingState(
        current_phase=5,
        phase1=phase1,
        phase2=phase2,
        phase3=phase3,
        phase4=phase4,
    )

    console.print("\n[bold cyan]Phase 5 of 5: Configuration Summary & Export[/bold cyan]")
    console.print(Panel(Markdown(state.to_summary_markdown()), border_style="green"))

    generator = InfrastructureGenerator()
    export_path = generator.export_to_directory(state, base_output_dir=output_dir)

    console.print(
        f"\n[bold green]Successfully generated modular Terraform & CI/CD bundle at:[/bold green] [underline]{export_path}[/underline]"
    )
    rendered_files = generator.render_bundle(state)
    console.print("\n[bold]Preview of Root `main.tf`:[/bold]")
    console.print(Syntax(rendered_files["main.tf"], "hcl", theme="monokai", line_numbers=True))


if __name__ == "__main__":
    app()
