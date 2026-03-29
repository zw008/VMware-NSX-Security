"""DFW policy CRUD operations.

Covers NSX Distributed Firewall security policies via the Policy API:
  GET/PUT/PATCH/DELETE /policy/api/v1/infra/domains/default/security-policies/...
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from vmware_policy import sanitize

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.dfw_policy")

_DFW_BASE = "/policy/api/v1/infra/domains/default/security-policies"


def _validate_id(value: str, field: str = "id") -> str:
    """Validate that an ID contains only safe characters.

    Allowed: alphanumerics, hyphens, underscores, dots.

    Args:
        value: The ID string to validate.
        field: Field name for error messages.

    Returns:
        The validated ID string.

    Raises:
        ValueError: If the ID contains disallowed characters.
    """
    if not re.match(r"^[\w\-\.]+$", value):
        raise ValueError(
            f"Invalid {field} '{value}': only alphanumerics, hyphens, "
            "underscores, and dots are allowed."
        )
    return value


# ---------------------------------------------------------------------------
# Policy list / get
# ---------------------------------------------------------------------------


def list_dfw_policies(client: NsxClient) -> list[dict]:
    """List all DFW security policies in the default domain.

    Args:
        client: Authenticated NsxClient instance.

    Returns:
        List of policy summary dicts with id, display_name, category,
        sequence_number, and rule count.
    """
    items = client.get_all(_DFW_BASE)
    return [
        {
            "id": sanitize(p.get("id", "")),
            "display_name": sanitize(p.get("display_name", "")),
            "category": sanitize(p.get("category", "")),
            "sequence_number": p.get("sequence_number", 0),
            "stateful": p.get("stateful", True),
            "tcp_strict": p.get("tcp_strict", False),
            "rule_count": p.get("rule_count", 0),
            "path": sanitize(p.get("path", "")),
        }
        for p in items
    ]


def get_dfw_policy(client: NsxClient, policy_id: str) -> dict:
    """Get details of a single DFW security policy.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Policy identifier (e.g. 'app-tier-policy').

    Returns:
        Policy detail dict including metadata and rule summary.
    """
    _validate_id(policy_id, "policy_id")
    p = client.get(f"{_DFW_BASE}/{policy_id}")
    return {
        "id": sanitize(p.get("id", "")),
        "display_name": sanitize(p.get("display_name", "")),
        "description": sanitize(p.get("description", "")),
        "category": sanitize(p.get("category", "")),
        "sequence_number": p.get("sequence_number", 0),
        "stateful": p.get("stateful", True),
        "tcp_strict": p.get("tcp_strict", False),
        "locked": p.get("locked", False),
        "scope": p.get("scope", []),
        "tags": p.get("tags", []),
        "path": sanitize(p.get("path", "")),
        "_revision": p.get("_revision"),
    }


# ---------------------------------------------------------------------------
# Policy create / update / delete
# ---------------------------------------------------------------------------


def create_dfw_policy(
    client: NsxClient,
    policy_id: str,
    display_name: str,
    category: str = "Application",
    sequence_number: int = 10,
    stateful: bool = True,
    description: str = "",
) -> dict:
    """Create a new DFW security policy via PUT.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Unique policy ID (alphanumeric + hyphens).
        display_name: Human-readable policy name.
        category: Policy category — one of Emergency, Infrastructure,
            Environment, Application (default: Application).
        sequence_number: Priority order (lower = higher priority).
        stateful: Whether the firewall tracks connection state (default True).
        description: Optional description string.

    Returns:
        Created policy dict as returned by the API.
    """
    _validate_id(policy_id, "policy_id")
    body: dict[str, Any] = {
        "display_name": sanitize(display_name),
        "category": category,
        "sequence_number": sequence_number,
        "stateful": stateful,
    }
    if description:
        body["description"] = sanitize(description)

    result = client.put(f"{_DFW_BASE}/{policy_id}", body)
    _log.info("Created DFW policy: %s (%s)", policy_id, category)
    return result


def update_dfw_policy(
    client: NsxClient,
    policy_id: str,
    display_name: str | None = None,
    description: str | None = None,
    sequence_number: int | None = None,
    stateful: bool | None = None,
) -> dict:
    """Partially update a DFW security policy via PATCH.

    Only the fields explicitly passed will be modified.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: ID of the policy to update.
        display_name: New display name (optional).
        description: New description (optional).
        sequence_number: New sequence number (optional).
        stateful: New stateful flag value (optional).

    Returns:
        Updated policy dict as returned by the API.
    """
    _validate_id(policy_id, "policy_id")
    body: dict[str, Any] = {}
    if display_name is not None:
        body["display_name"] = sanitize(display_name)
    if description is not None:
        body["description"] = sanitize(description)
    if sequence_number is not None:
        body["sequence_number"] = sequence_number
    if stateful is not None:
        body["stateful"] = stateful

    if not body:
        raise ValueError("No fields provided to update.")

    result = client.patch(f"{_DFW_BASE}/{policy_id}", body)
    _log.info("Updated DFW policy: %s", policy_id)
    return result


def delete_dfw_policy(client: NsxClient, policy_id: str) -> dict[str, str]:
    """Delete a DFW security policy after checking for active rules.

    Refuses deletion if the policy contains any rules, to prevent
    accidental removal of active security posture.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: ID of the policy to delete.

    Returns:
        Dict with 'status' and 'message' keys on success.

    Raises:
        ValueError: If the policy still contains active rules.
    """
    _validate_id(policy_id, "policy_id")
    rules = list_dfw_rules(client, policy_id)
    if rules:
        rule_ids = [r["id"] for r in rules]
        raise ValueError(
            f"Cannot delete policy '{policy_id}': it contains {len(rules)} rule(s). "
            f"Delete the following rules first: {rule_ids}"
        )

    client.delete(f"{_DFW_BASE}/{policy_id}")
    _log.info("Deleted DFW policy: %s", policy_id)
    return {"status": "deleted", "message": f"DFW policy '{policy_id}' deleted."}


# ---------------------------------------------------------------------------
# Rules list
# ---------------------------------------------------------------------------


def list_dfw_rules(client: NsxClient, policy_id: str) -> list[dict]:
    """List all rules under a DFW security policy.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Policy ID whose rules to list.

    Returns:
        List of rule summary dicts with id, display_name, action, sources,
        destinations, services, scope, and hit-count fields.
    """
    _validate_id(policy_id, "policy_id")
    items = client.get_all(f"{_DFW_BASE}/{policy_id}/rules")
    return [
        {
            "id": sanitize(r.get("id", "")),
            "display_name": sanitize(r.get("display_name", "")),
            "action": r.get("action", "ALLOW"),
            "sources": r.get("source_groups", []),
            "destinations": r.get("destination_groups", []),
            "services": r.get("services", []),
            "scope": r.get("scope", []),
            "direction": r.get("direction", "IN_OUT"),
            "ip_protocol": r.get("ip_protocol", "IPV4_IPV6"),
            "disabled": r.get("disabled", False),
            "logged": r.get("logged", False),
            "sequence_number": r.get("sequence_number", 0),
            "path": sanitize(r.get("path", "")),
        }
        for r in items
    ]
