"""IDPS (Intrusion Detection and Prevention System) query operations.

NSX IDPS provides network-layer intrusion detection with optional inline
prevention mode. This module provides read-only access to IDPS profiles
and engine status.

APIs used:
  GET /policy/api/v1/infra/settings/firewall/security/intrusion-services/profiles
  GET /policy/api/v1/infra/settings/firewall/security/intrusion-services/status
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from vmware_policy import sanitize

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.idps")

_IDPS_BASE = "/policy/api/v1/infra/settings/firewall/security/intrusion-services"


# ---------------------------------------------------------------------------
# IDPS Profiles
# ---------------------------------------------------------------------------


def list_idps_profiles(client: NsxClient) -> list[dict]:
    """List all IDPS profiles configured in NSX.

    IDPS profiles define which signature sets and actions (detect/prevent)
    are active. Each profile can be applied to one or more DFW policies.

    Args:
        client: Authenticated NsxClient instance.

    Returns:
        List of IDPS profile summary dicts with id, display_name,
        overridden signature counts, and criteria.
    """
    items = client.get_all(f"{_IDPS_BASE}/profiles")
    return [
        {
            "id": sanitize(p.get("id", "")),
            "display_name": sanitize(p.get("display_name", "")),
            "description": sanitize(p.get("description", "")),
            "criteria": [
                {
                    "attack_types": c.get("attack_types", []),
                    "attack_targets": c.get("attack_targets", []),
                    "cvss": c.get("cvss", {}),
                    "products_affected": c.get("products_affected", []),
                }
                for c in p.get("criteria", [])
            ],
            "profile_severity": sanitize(p.get("profile_severity", "")),
            "overridden_signature_count": p.get("overridden_signature_count", 0),
            "path": sanitize(p.get("path", "")),
        }
        for p in items
    ]


# ---------------------------------------------------------------------------
# IDPS Engine Status
# ---------------------------------------------------------------------------


def get_idps_status(client: NsxClient) -> dict:
    """Get the current IDPS engine status across all transport nodes.

    Returns engine enable/disable state, signature version, last update
    time, and per-node status summary.

    Args:
        client: Authenticated NsxClient instance.

    Returns:
        Dict with global_status (ENABLED/DISABLED), signature_version,
        last_signature_update, and node_status_counts.
    """
    try:
        status = client.get(f"{_IDPS_BASE}/status")
    except Exception as exc:
        _log.warning("Failed to fetch IDPS global status: %s", exc)
        status = {}

    # Per-node status summary
    node_counts: dict[str, int] = {}
    try:
        node_data = client.get(f"{_IDPS_BASE}/node-status")
        for node in node_data.get("results", []):
            state = sanitize(node.get("node_status", "UNKNOWN"))
            node_counts[state] = node_counts.get(state, 0) + 1
    except Exception as exc:
        _log.debug("Could not fetch per-node IDPS status: %s", exc)

    return {
        "global_status": sanitize(status.get("status", "UNKNOWN")),
        "signature_version": sanitize(str(status.get("signature_version", ""))),
        "last_signature_update": sanitize(str(status.get("last_signature_update_time", ""))),
        "signatures_up_to_date": status.get("signatures_up_to_date", False),
        "node_status_counts": node_counts,
    }
