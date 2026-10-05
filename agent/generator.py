"""Jinja2 template rendering orchestrator for Terraform and CI/CD pipelines."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from agent.state import CicdProvider, OnboardingState, WorkloadType

TEMPLATES_ROOT = Path(__file__).resolve().parent.parent / "templates"


class InfrastructureGenerator:
    """Renders modular Terraform configurations and CI/CD pipelines from OnboardingState."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        self.templates_dir = (templates_dir or TEMPLATES_ROOT).resolve()
        if not self.templates_dir.is_dir():
            raise FileNotFoundError(
                f"Templates directory not found at '{self.templates_dir}'."
            )
        # Note: Terraform HCL and YAML files are non-HTML infrastructure manifests;
        # all user inputs are strictly allow-listed via Pydantic regex/CIDR validators
        # in agent/validators.py and agent/state.py prior to rendering.
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
            autoescape=False,  # nosec: generating HCL/YAML, inputs validated via strict allow-lists
        )

    def render_bundle(self, state: OnboardingState) -> Dict[str, str]:
        """Render all Terraform root files, active modules, and CI/CD manifest in memory.

        Returns a mapping of relative file paths to rendered file contents.
        """
        ctx = {
            "state": state,
            "phase1": state.phase1,
            "phase2": state.phase2,
            "phase3": state.phase3,
            "phase4": state.phase4,
            "workload_type": state.phase3.workload_type.value,
        }

        rendered: Dict[str, str] = {}

        # 1. Root Terraform files
        root_templates = {
            "versions.tf": "terraform/versions.tf.j2",
            "main.tf": "terraform/main.tf.j2",
            "variables.tf": "terraform/variables.tf.j2",
            "terraform.tfvars": "terraform/terraform.tfvars.j2",
            "outputs.tf": "terraform/outputs.tf.j2",
        }
        for out_path, tpl_path in root_templates.items():
            rendered[out_path] = self.env.get_template(tpl_path).render(**ctx)

        # 2. Networking module (always included)
        networking_templates = {
            "modules/networking/main.tf": "terraform/modules/networking/main.tf.j2",
            "modules/networking/variables.tf": "terraform/modules/networking/variables.tf.j2",
            "modules/networking/outputs.tf": "terraform/modules/networking/outputs.tf.j2",
        }
        for out_path, tpl_path in networking_templates.items():
            rendered[out_path] = self.env.get_template(tpl_path).render(**ctx)

        # 3. Workload-specific database module
        workload_module_map = {
            WorkloadType.ADB: (
                "modules/adb/main.tf",
                "terraform/modules/adb/main.tf.j2",
            ),
            WorkloadType.EXADATA_DEDICATED: (
                "modules/exadata_dedicated/main.tf",
                "terraform/modules/exadata_dedicated/main.tf.j2",
            ),
            WorkloadType.EXASCALE: (
                "modules/exascale/main.tf",
                "terraform/modules/exascale/main.tf.j2",
            ),
            WorkloadType.BASEDB: (
                "modules/basedb/main.tf",
                "terraform/modules/basedb/main.tf.j2",
            ),
        }
        mod_out, mod_tpl = workload_module_map[state.phase3.workload_type]
        rendered[mod_out] = self.env.get_template(mod_tpl).render(**ctx)

        # 4. CI/CD Pipeline manifest
        pipeline_map = {
            CicdProvider.GITHUB_ACTIONS: (
                ".github/workflows/deploy-odb.yml",
                "pipelines/github-actions.yml.j2",
            ),
            CicdProvider.GITLAB_CI: (
                ".gitlab-ci.yml",
                "pipelines/gitlab-ci.yml.j2",
            ),
            CicdProvider.CLOUDBUILD: (
                "cloudbuild.yaml",
                "pipelines/cloudbuild.yaml.j2",
            ),
        }
        pipe_out, pipe_tpl = pipeline_map[state.phase4.cicd_provider]
        rendered[pipe_out] = self.env.get_template(pipe_tpl).render(**ctx)

        # 5. Summary Markdown
        rendered["DEPLOYMENT_SUMMARY.md"] = state.to_summary_markdown() + "\n"

        return rendered

    def export_to_directory(
        self,
        state: OnboardingState,
        base_output_dir: Path | str = ".",
        folder_name: str | None = None,
    ) -> Path:
        """Safely write rendered Terraform and CI/CD files to an export directory."""
        base_resolved = Path(base_output_dir).resolve()
        base_resolved.mkdir(parents=True, exist_ok=True)

        if folder_name:
            safe_folder = os.path.basename(folder_name.strip())
            if not safe_folder or safe_folder in {".", ".."}:
                raise ValueError(f"Invalid export folder name: '{folder_name}'")
        else:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            safe_folder = f"generated-tf-{ts}"

        export_root = (base_resolved / safe_folder).resolve()
        if not str(export_root).startswith(str(base_resolved) + os.sep):
            raise ValueError("Export directory escapes base output boundary.")

        bundle = self.render_bundle(state)

        for rel_path, content in bundle.items():
            # Verify each relative output path stays strictly inside export_root
            target_file = (export_root / rel_path).resolve()
            if not str(target_file).startswith(str(export_root) + os.sep):
                raise ValueError(f"Unsafe relative path detected: '{rel_path}'")
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(content, encoding="utf-8")

        return export_root
