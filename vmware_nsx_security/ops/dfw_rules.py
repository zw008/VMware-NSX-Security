"""DFW rule CRUD and statistics operations.

Covers individual rule management under a security policy:
  PUT/PATCH/DELETE /policy/api/v1/infra/domains/default/security-policies/<id>/rules/<rule-id>
  GET              /policy/api/v1/infra/domains/default/security-policies/<id>/rules/<rule-id>/statistics
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.dfw_rules")

_DFW_BASE = "/policy/api/v1/infra/domains/default/security-policies"

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

_VALID_ACTIONS = {"ALLOW", "DROP", "REJECT", "JUMP_TO_APPLICATION"}
_VALID_DIRECTIONS = {"IN", "OUT", "IN_OUT"}
_VALID_IP_PROTOS = {"IPV4", "IPV6", "IPV4_IPV6"}


def _sanitize(text: str, max_len: int = 500) -> str:
    """Strip control characters and truncate to max_len."""
    if not text:
        return text
    return _CONTROL_CHAR_RE.sub("", text[:max_len])


def _validate_id(value: str, field: str = "id") -> str:
    """Validate that an ID contains only safe characters."""
    if not re.match(r"^[\w\-\.]+$", value):
        raise ValueError(
            f"Invalid {field} '{value}': only alphanumerics, hyphens, "
            "underscores, and dots are allowed."
        )
    return value


# ---------------------------------------------------------------------------
# Rule CRUD
# ---------------------------------------------------------------------------


def create_dfw_rule(
    client: NsxClient,
    policy_id: str,
    rule_id: str,
    display_name: str,
    action: str = "ALLOW",
    sources: list[str] | None = None,
    destinations: list[str] | None = None,
    services: list[str] | None = None,
    scope: list[str] | None = None,
    direction: str = "IN_OUT",
    ip_protocol: str = "IPV4_IPV6",
    logged: bool = False,
    disabled: bool = False,
    sequence_number: int = 10,
    description: str = "",
) -> dict:
    """Create a DFW rule under the given policy via PUT.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Parent policy ID.
        rule_id: Unique rule identifier (alphanumeric + hyphens).
        display_name: Human-readable rule name.
        action: Firewall action — ALLOW, DROP, REJECT, or
            JUMP_TO_APPLICATION (default: ALLOW).
        sources: List of source group paths or 'ANY' (default: ANY).
        destinations: List of destination group paths or 'ANY' (default: ANY).
        services: List of service paths or 'ANY' (default: ANY).
        scope: List of scope paths (groups/segments) the rule applies to.
        direction: Traffic direction — IN, OUT, or IN_OUT (default: IN_OUT).
        ip_protocol: IP version — IPV4, IPV6, or IPV4_IPV6 (default: IPV4_IPV6).
        logged: Whether to log matching traffic (default False).
        disabled: Whether the rule is disabled (default False).
        sequence_number: Rule priority within the policy.
        description: Optional description.

    Returns:
        Created rule dict as returned by the API.

    Raises:
        ValueError: If action, direction, or ip_protocol is invalid.
    """
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")

    if action not in _VALID_ACTIONS:
        raise ValueError(f"Invalid action '{action}'. Must be one of: {_VALID_ACTIONS}")
    if direction not in _VALID_DIRECTIONS:
        raise ValueError(f"Invalid direction '{direction}'. Must be one of: {_VALID_DIRECTIONS}")
    if ip_protocol not in _VALID_IP_PROTOS:
        raise ValueError(f"Invalid ip_protocol '{ip_protocol}'. Must be one of: {_VALID_IP_PROTOS}")

    body: dict[str, Any] = {
        "display_name": _sanitize(display_name),
        "action": action,
        "source_groups": sources if sources is not None else ["ANY"],
        "destination_groups": destinations if destinations is not None else ["ANY"],
        "services": services if services is not None else ["ANY"],
        "direction": direction,
        "ip_protocol": ip_protocol,
        "logged": logged,
        "disabled": disabled,
        "sequence_number": sequence_number,
    }
    if scope:
        body["scope"] = scope
    if description:
        body["description"] = _sanitize(description)

    result = client.put(f"{_DFW_BASE}/{policy_id}/rules/{rule_id}", body)
    _log.info("Created DFW rule: %s in policy %s (action=%s)", rule_id, policy_id, action)
    return result


def update_dfw_rule(
    client: NsxClient,
    policy_id: str,
    rule_id: str,
    display_name: str | None = None,
    action: str | None = None,
    sources: list[str] | None = None,
    destinations: list[str] | None = None,
    services: list[str] | None = None,
    logged: bool | None = None,
    disabled: bool | None = None,
    sequence_number: int | None = None,
    description: str | None = None,
) -> dict:
    """Partially update a DFW rule via PATCH.

    Only explicitly provided fields are modified.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Parent policy ID.
        rule_id: ID of the rule to update.
        display_name: New display name (optional).
        action: New action (optional).
        sources: New source groups (optional).
        destinations: New destination groups (optional).
        services: New services list (optional).
        logged: New logged flag (optional).
        disabled: New disabled flag (optional).
        sequence_number: New sequence number (optional).
        description: New description (optional).

    Returns:
        Updated rule dict as returned by the API.
    """
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")

    if action is not None and action not in _VALID_ACTIONS:
        raise ValueError(f"Invalid action '{action}'. Must be one of: {_VALID_ACTIONS}")

    body: dict[str, Any] = {}
    if display_name is not None:
        body["display_name"] = _sanitize(display_name)
    if action is not None:
        body["action"] = action
    if sources is not None:
        body["source_groups"] = sources
    if destinations is not None:
        body["destination_groups"] = destinations
    if services is not None:
        body["services"] = services
    if logged is not None:
        body["logged"] = logged
    if disabled is not None:
        body["disabled"] = disabled
    if sequence_number is not None:
        body["sequence_number"] = sequence_number
    if description is not None:
        body["description"] = _sanitize(description)

    if not body:
        raise ValueError("No fields provided to update.")

    result = client.patch(f"{_DFW_BASE}/{policy_id}/rules/{rule_id}", body)
    _log.info("Updated DFW rule: %s in policy %s", rule_id, policy_id)
    return result


def delete_dfw_rule(client: NsxClient, policy_id: str, rule_id: str) -> dict[str, str]:
    """Delete a DFW rule from the given policy.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Parent policy ID.
        rule_id: ID of the rule to delete.

    Returns:
        Dict with 'status' and 'message' keys on success.
    """
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")

    client.delete(f"{_DFW_BASE}/{policy_id}/rules/{rule_id}")
    _log.info("Deleted DFW rule: %s from policy %s", rule_id, policy_id)
    return {
        "status": "deleted",
        "message": f"DFW rule '{rule_id}' deleted from policy '{policy_id}'.",
    }


# ---------------------------------------------------------------------------
# Rule statistics
# ---------------------------------------------------------------------------


def get_dfw_rule_stats(client: NsxClient, policy_id: str, rule_id: str) -> dict:
    """Get hit-count statistics for a DFW rule.

    Returns packet and byte counters showing how many times the rule
    has been matched by traffic.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Parent policy ID.
        rule_id: ID of the rule to query statistics for.

    Returns:
        Statistics dict with packet_count, byte_count, session_count,
        and population_count (number of hosts where rule is realised).
    """
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")

    stats = client.get(
        f"{_DFW_BASE}/{policy_id}/rules/{rule_id}/statistics"
    )
    # NSX returns an array of per-firewall-section stats; sum them up
    results = stats.get("results", [stats])
    total_packets = sum(r.get("packet_count", 0) for r in results)
    total_bytes = sum(r.get("byte_count", 0) for r in results)
    total_sessions = sum(r.get("session_count", 0) for r in results)
    population = stats.get("population_count", len(results))

    return {
        "policy_id": policy_id,
        "rule_id": rule_id,
        "packet_count": total_packets,
        "byte_count": total_bytes,
        "session_count": total_sessions,
        "population_count": population,
        "raw": results,
    }
