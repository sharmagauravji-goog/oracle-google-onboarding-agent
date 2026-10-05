"""Strict CIDR, naming, SSH key, and catalog validation functions for ODB@GCP."""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Tuple

# RFC 1035 / GCP resource identifier: 1-63 lowercase alphanumeric with hyphens
GCP_RESOURCE_ID_REGEX = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
GCP_PROJECT_ID_REGEX = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
GCP_REGION_REGEX = re.compile(r"^[a-z]+-[a-z]+[0-9]+$")
GCP_ORACLE_ZONE_REGEX = re.compile(r"^[a-z]+-[a-z]+[0-9]+-[a-z]-r[0-9]+$")
ORACLE_DB_NAME_REGEX = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,13}$")
HOSTNAME_PREFIX_REGEX = re.compile(r"^[a-z][a-z0-9-]{0,11}[a-z0-9]$")
GCS_BUCKET_REGEX = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
COST_CENTER_REGEX = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
SSH_PUBKEY_REGEX = re.compile(
    r"^(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/=]+(?:\s+[^\r\n]+)?$"
)

# Authoritative catalog of Google Cloud regions and GCP Oracle Zones for
# Oracle Database@Google Cloud per https://docs.cloud.google.com/oracle/database/docs/regions-and-zones
ODB_REGION_CATALOG: Dict[str, Dict[str, object]] = {
    # Asia Pacific
    "asia-northeast1": {
        "display_name": "asia-northeast1 — Tokyo, Japan (Asia Pacific)",
        "oracle_zones": ["asia-northeast1-a-r1"],
    },
    "asia-northeast2": {
        "display_name": "asia-northeast2 — Osaka, Japan (Asia Pacific)",
        "oracle_zones": ["asia-northeast2-a-r1"],
    },
    "australia-southeast1": {
        "display_name": "australia-southeast1 — Sydney, Australia (Asia Pacific)",
        "oracle_zones": ["australia-southeast1-b-r1"],
    },
    "australia-southeast2": {
        "display_name": "australia-southeast2 — Melbourne, Australia (Asia Pacific)",
        "oracle_zones": ["australia-southeast2-a-r2", "australia-southeast2-b-r1"],
    },
    "asia-south1": {
        "display_name": "asia-south1 — Mumbai, India (Asia Pacific)",
        "oracle_zones": ["asia-south1-b-r1"],
    },
    "asia-south2": {
        "display_name": "asia-south2 — Delhi, India (Asia Pacific)",
        "oracle_zones": ["asia-south2-b-r1"],
    },
    # North America
    "northamerica-northeast1": {
        "display_name": "northamerica-northeast1 — Montréal, Québec, Canada (North America)",
        "oracle_zones": ["northamerica-northeast1-a-r1"],
    },
    "northamerica-northeast2": {
        "display_name": "northamerica-northeast2 — Toronto, Ontario, Canada (North America)",
        "oracle_zones": ["northamerica-northeast2-a-r2"],
    },
    "us-central1": {
        "display_name": "us-central1 — Iowa (North America)",
        "oracle_zones": ["us-central1-a-r1"],
    },
    "us-east4": {
        "display_name": "us-east4 — Northern Virginia (North America)",
        "oracle_zones": ["us-east4-a-r2", "us-east4-b-r1"],
    },
    "us-west3": {
        "display_name": "us-west3 — Salt Lake City (North America)",
        "oracle_zones": ["us-west3-a-r1"],
    },
    # South America
    "southamerica-east1": {
        "display_name": "southamerica-east1 — São Paulo, Brazil (South America)",
        "oracle_zones": ["southamerica-east1-a-r1"],
    },
    # Europe
    "europe-west2": {
        "display_name": "europe-west2 — London, England (Europe)",
        "oracle_zones": ["europe-west2-a-r1", "europe-west2-c-r2"],
    },
    "europe-west3": {
        "display_name": "europe-west3 — Frankfurt, Germany (Europe)",
        "oracle_zones": ["europe-west3-a-r2", "europe-west3-b-r1"],
    },
    "europe-west8": {
        "display_name": "europe-west8 — Milan, Italy (Europe)",
        "oracle_zones": ["europe-west8-b-r1", "europe-west8-a-r1"],
    },
    "europe-west12": {
        "display_name": "europe-west12 — Turin, Italy (Europe)",
        "oracle_zones": ["europe-west12-a-r1"],
    },
}

SUPPORTED_ODB_REGIONS = set(ODB_REGION_CATALOG.keys())

# Exadata Dedicated Hardware Shapes
SUPPORTED_EXADATA_SHAPES: Dict[str, str] = {
    "Exadata.X11M": "Exadata.X11M — Latest Gen (AMD EPYC 4th Gen, RoCEv2, X11M Extreme Flash/HC)",
    "Exadata.X9M": "Exadata.X9M — Enterprise Standard (Intel Xeon Ice Lake, RoCEv2, PMEM)",
    "Exadata.X8M": "Exadata.X8M — Previous Gen (Intel Xeon Cascade Lake, RoCEv2)",
}

# Supported Grid Infrastructure (GI) versions
SUPPORTED_GI_VERSIONS_DEDICATED: Dict[str, str] = {
    "23.0.0.0": "23.0.0.0 — Oracle Grid Infrastructure 23ai (Recommended)",
    "23.5.0.24.07": "23.5.0.24.07 — Oracle Grid Infrastructure 23ai Release Update 23.5",
    "19.0.0.0": "19.0.0.0 — Oracle Grid Infrastructure 19c Long Term Support (LTS)",
    "19.24.0.0.240716": "19.24.0.0.240716 — Oracle Grid Infrastructure 19c RU 19.24",
    "19.23.0.0.240416": "19.23.0.0.240416 — Oracle Grid Infrastructure 19c RU 19.23",
}

SUPPORTED_GI_VERSIONS_EXASCALE: Dict[str, str] = {
    "23.0.0.0": "23.0.0.0 — Oracle Grid Infrastructure 23ai (Default for Exascale)",
    "23.5.0.24.07": "23.5.0.24.07 — Oracle Grid Infrastructure 23ai Release Update 23.5",
    "23.4.0.24.05": "23.4.0.24.05 — Oracle Grid Infrastructure 23ai Release Update 23.4",
}

# Supported Base Database Service compute shapes
SUPPORTED_BASEDB_SHAPES: Dict[str, str] = {
    "VM.Standard.E5.Flex": "VM.Standard.E5.Flex — AMD EPYC 4th Gen Genoa Flexible VM",
    "VM.Standard.E4.Flex": "VM.Standard.E4.Flex — AMD EPYC 3rd Gen Milan Flexible VM",
    "VM.Standard3.Flex": "VM.Standard3.Flex — Intel Xeon Ice Lake Flexible VM",
    "VM.Optimized3.Flex": "VM.Optimized3.Flex — High-Frequency Intel Xeon Flexible VM",
}

SUPPORTED_CHARACTER_SETS: List[str] = [
    "AL32UTF8",
    "US7ASCII",
    "WE8ISO8859P1",
    "WE8MSWIN1252",
    "JA16SJIS",
    "ZHS16GBK",
]

SUPPORTED_TIMEZONES: List[str] = [
    "UTC",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Toronto",
    "America/Sao_Paulo",
    "Europe/London",
    "Europe/Frankfurt",
    "Europe/Paris",
    "Europe/Zurich",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Asia/Kolkata",
    "Australia/Sydney",
]


def get_region_display_name(region: str) -> str:
    """Return human-friendly display name for a GCP region."""
    entry = ODB_REGION_CATALOG.get(region)
    if entry and isinstance(entry.get("display_name"), str):
        return str(entry["display_name"])
    return region


def get_oracle_zones_for_region(region: str) -> List[str]:
    """Return available GCP Oracle Zones for a given Google Cloud region."""
    cleaned = region.strip().lower()
    entry = ODB_REGION_CATALOG.get(cleaned)
    if entry and isinstance(entry.get("oracle_zones"), list):
        return [str(z) for z in entry["oracle_zones"]]  # type: ignore[union-attr]
    raise ValueError(
        f"Unsupported Oracle Database@Google Cloud region '{region}'. "
        f"Supported regions: {', '.join(sorted(ODB_REGION_CATALOG.keys()))}"
    )


def validate_gcp_resource_id(value: str, field_name: str = "resource_id") -> str:
    """Validate GCP resource identifier (1-63 lowercase alphanumeric with hyphens)."""
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 63 or not GCP_RESOURCE_ID_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid {field_name} '{value}': must be 1-63 characters, start with a lowercase "
            "letter, end with a lowercase letter or digit, and contain only lowercase letters, "
            "digits, and hyphens."
        )
    return cleaned


def validate_gcp_project_id(value: str, field_name: str = "project_id") -> str:
    """Validate Google Cloud Project ID format (6-30 lowercase chars, digits, hyphens)."""
    cleaned = value.strip()
    if not GCP_PROJECT_ID_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid {field_name} '{value}': must be 6-30 characters, start with a lowercase "
            "letter, and contain only lowercase letters, numbers, and hyphens."
        )
    return cleaned


def validate_region(value: str) -> str:
    """Validate Google Cloud region string against supported ODB@GCP regions."""
    cleaned = value.strip().lower()
    if not GCP_REGION_REGEX.match(cleaned) or cleaned not in SUPPORTED_ODB_REGIONS:
        raise ValueError(
            f"Invalid or unsupported ODB@GCP region '{value}'. Must be one of: "
            f"{', '.join(sorted(SUPPORTED_ODB_REGIONS))}."
        )
    return cleaned


def validate_oracle_zone(value: str, region: str | None = None) -> str:
    """Validate GCP Oracle Zone identifier (e.g., 'us-central1-a-r1') and region alignment."""
    cleaned = value.strip().lower()
    if not GCP_ORACLE_ZONE_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid gcp_oracle_zone '{value}': expected format '<region>-<zone>-r<num>' "
            "(e.g., 'us-east4-a-r2' or 'us-east4-b-r1')."
        )
    if region:
        clean_region = region.strip().lower()
        if not cleaned.startswith(f"{clean_region}-"):
            raise ValueError(
                f"GCP Oracle Zone '{cleaned}' does not belong to target region '{region}'."
            )
        valid_zones = get_oracle_zones_for_region(clean_region)
        if cleaned not in valid_zones:
            raise ValueError(
                f"GCP Oracle Zone '{cleaned}' is not a supported Oracle zone in region "
                f"'{clean_region}'. Supported zones for {clean_region}: {', '.join(valid_zones)}."
            )
    return cleaned


def validate_cidr_block(
    cidr: str,
    field_name: str = "cidr_range",
    min_prefix: int = 8,
    max_prefix: int = 28,
) -> str:
    """Validate an IPv4 CIDR block and enforce minimum subnet size (/28 max prefix length)."""
    cleaned = cidr.strip()
    try:
        net = ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR block for {field_name} ('{cidr}'): {exc}") from exc

    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError(f"{field_name} ('{cidr}') must be an IPv4 CIDR block.")

    if net.prefixlen < min_prefix or net.prefixlen > max_prefix:
        raise ValueError(
            f"{field_name} ('{cidr}') has prefix length /{net.prefixlen}; "
            f"must be between /{min_prefix} and /{max_prefix} (minimum subnet size is /{max_prefix})."
        )

    if not net.is_private:
        raise ValueError(
            f"{field_name} ('{cidr}') must use private RFC 1918 IPv4 address space "
            "(10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16)."
        )

    return str(net)


def validate_non_overlapping_cidrs(named_cidrs: Dict[str, str | None]) -> None:
    """Ensure all provided CIDR blocks are mutually non-overlapping."""
    parsed: List[Tuple[str, ipaddress.IPv4Network]] = []
    for name, cidr in named_cidrs.items():
        if not cidr:
            continue
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError(f"CIDR '{name}' ({cidr}) must be a valid IPv4 network.")
        for existing_name, existing_net in parsed:
            if net.overlaps(existing_net):
                raise ValueError(
                    f"CIDR overlap detected: {name} ({net}) overlaps with "
                    f"{existing_name} ({existing_net}). ODB subnets must not overlap with "
                    "the Google Cloud VPC or each other."
                )
        parsed.append((name, net))


def validate_oracle_db_name(value: str) -> str:
    """Validate Oracle Database Name (1-14 alphanumeric/underscore characters, starting with letter)."""
    cleaned = value.strip()
    if not ORACLE_DB_NAME_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid Oracle Database name '{value}': must be 1-14 characters, begin with a letter, "
            "and contain only letters, digits, or underscores."
        )
    return cleaned


def validate_hostname_prefix(value: str) -> str:
    """Validate VM Cluster / DB System hostname prefix (2-13 lowercase alphanumeric/hyphens)."""
    cleaned = value.strip().lower()
    if not HOSTNAME_PREFIX_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid hostname_prefix '{value}': must be 2-13 characters, start with a lowercase "
            "letter, end with a lowercase letter or digit, and contain only lowercase letters, "
            "digits, and hyphens."
        )
    return cleaned


def validate_ssh_public_key(key: str) -> str:
    """Validate an OpenSSH public key string."""
    cleaned = key.strip()
    if not SSH_PUBKEY_REGEX.match(cleaned):
        raise ValueError(
            "Invalid SSH public key: must start with 'ssh-rsa', 'ssh-ed25519', or "
            "'ecdsa-sha2-nistp256/384/521' followed by a base64-encoded key."
        )
    return cleaned


def validate_gcs_bucket_name(bucket: str) -> str:
    """Validate a Google Cloud Storage bucket name."""
    cleaned = bucket.strip().lower()
    if not GCS_BUCKET_REGEX.match(cleaned) or ".." in cleaned:
        raise ValueError(
            f"Invalid GCS bucket name '{bucket}': must be 3-63 lowercase characters "
            "(letters, digits, hyphens, underscores, dots) and start/end with alphanumeric."
        )
    return cleaned


def validate_cost_center(value: str) -> str:
    """Validate enterprise FinOps cost center label value (1-63 lowercase chars, digits, hyphens, underscores)."""
    cleaned = value.strip().lower()
    if not COST_CENTER_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid cost_center '{value}': must be 1-63 lowercase alphanumeric characters, hyphens, or underscores."
        )
    return cleaned
