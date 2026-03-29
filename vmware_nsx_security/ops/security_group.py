"""Security group (NSX Group) CRUD operations.

Covers the NSX Policy Groups API:
  GET/PUT/DELETE /policy/api/v1/infra/domains/default/groups/...

Groups can be defined by VM tags, segment membership, IP addresses,
or combinations thereof (AND/OR expressions).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from vmware_policy import sanitize

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.security_group")

_GROUPS_BASE = "/policy/api/v1/infra/domains/default/groups"
_DFW_POLICIES_BASE = "/policy/api/v1/infra/domains/default/security-policies"


def _validate_id(value: str, field: str = "id") -> str:
    """Validate that an ID contains only safe characters."""
    if not re.match(r"^[\w\-\.]+$", value):
        raise ValueError(
            f"Invalid {field} '{value}': only alphanumerics, hyphens, "
            "underscores, and dots are allowed."
        )
    return value


# ---------------------------------------------------------------------------
# Group list / get
# ---------------------------------------------------------------------------


def list_groups(client: NsxClient) -> list[dict]:
    """List all security groups in the default domain.

    Args:
        client: Authenticated NsxClient instance.

    Returns:
        List of group summary dicts with id, display_name, expression
        type counts, and member count.
    """
    items = client.get_all(_GROUPS_BASE)
    return [
        {
            "id": sanitize(g.get("id", "")),
            "display_name": sanitize(g.get("display_name", "")),
            "description": sanitize(g.get("description", "")),
            "expression_count": len(g.get("expression", [])),
            "tags": g.get("tags", []),
            "path": sanitize(g.get("path", "")),
        }
        for g in items
    ]


def get_group(client: NsxClient, group_id: str) -> dict:
    """Get details of a security group including its membership criteria.

    Args:
        client: Authenticated NsxClient instance.
        group_id: Group identifier (e.g. 'web-tier-vms').

    Returns:
        Group detail dict with id, display_name, expression rules,
        and member paths (up to 50 effective members).
    """
    _validate_id(group_id, "group_id")
    g = client.get(f"{_GROUPS_BASE}/{group_id}")

    # Try to get effective members
    members: list[dict] = []
    try:
        member_data = client.get(
            f"{_GROUPS_BASE}/{group_id}/members/virtual-machines"
        )
        members = [
            {
                "id": sanitize(m.get("external_id", "")),
                "display_name": sanitize(m.get("display_name", "")),
                "type": "VirtualMachine",
            }
            for m in member_data.get("results", [])[:50]
        ]
    except Exception:
        _log.debug("Could not fetch members for group %s", group_id)

    return {
        "id": sanitize(g.get("id", "")),
        "display_name": sanitize(g.get("display_name", "")),
        "description": sanitize(g.get("description", "")),
        "expression": g.get("expression", []),
        "tags": g.get("tags", []),
        "path": sanitize(g.get("path", "")),
        "member_count": len(members),
        "members": members,
        "_revision": g.get("_revision"),
    }


# ---------------------------------------------------------------------------
# Group create / delete
# ---------------------------------------------------------------------------


def create_group(
    client: NsxClient,
    group_id: str,
    display_name: str,
    description: str = "",
    tag_scope: str | None = None,
    tag_value: str | None = None,
    ip_addresses: list[str] | None = None,
    segment_paths: list[str] | None = None,
) -> dict:
    """Create a security group with optional membership criteria.

    Membership criteria are applied in order:
    1. If ``tag_scope`` and/or ``tag_value`` provided — VM tag condition.
    2. If ``ip_addresses`` provided — IPAddressExpression.
    3. If ``segment_paths`` provided — PathExpression for segments.

    Multiple criteria are ANDed together via a ``ConjunctionOperator``.

    Args:
        client: Authenticated NsxClient instance.
        group_id: Unique group identifier (alphanumeric + hyphens).
        display_name: Human-readable group name.
        description: Optional description.
        tag_scope: NSX tag scope for VM membership (e.g. 'env').
        tag_value: NSX tag value for VM membership (e.g. 'production').
        ip_addresses: List of IP addresses/CIDRs for IP-based membership.
        segment_paths: List of NSX segment policy paths for segment membership.

    Returns:
        Created group dict as returned by the API.
    """
    _validate_id(group_id, "group_id")

    expressions: list[dict[str, Any]] = []

    if tag_scope or tag_value:
        tag_expr: dict[str, Any] = {
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
        }
        if tag_scope:
            tag_expr["scope_operator"] = "EQUALS"
            tag_expr["tag"] = {"scope": sanitize(tag_scope), "tag": sanitize(tag_value or "")}
        else:
            tag_expr["tag"] = {"tag": sanitize(tag_value or "")}
        expressions.append(tag_expr)

    if ip_addresses:
        if expressions:
            expressions.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "AND"})
        expressions.append({
            "resource_type": "IPAddressExpression",
            "ip_addresses": ip_addresses,
        })

    if segment_paths:
        if expressions:
            expressions.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "AND"})
        expressions.append({
            "resource_type": "PathExpression",
            "paths": segment_paths,
        })

    body: dict[str, Any] = {
        "display_name": sanitize(display_name),
        "expression": expressions,
    }
    if description:
        body["description"] = sanitize(description)

    result = client.put(f"{_GROUPS_BASE}/{group_id}", body)
    _log.info("Created security group: %s", group_id)
    return result


def delete_group(client: NsxClient, group_id: str) -> dict[str, str]:
    """Delete a security group after checking for DFW policy references.

    Refuses deletion if the group is referenced by any DFW rule
    as a source or destination, to prevent breaking active security policies.

    Args:
        client: Authenticated NsxClient instance.
        group_id: ID of the group to delete.

    Returns:
        Dict with 'status' and 'message' keys on success.

    Raises:
        ValueError: If the group is referenced by DFW rules.
    """
    _validate_id(group_id, "group_id")

    # Build the path that would appear in DFW rules
    group_path = f"/infra/domains/default/groups/{group_id}"

    # Check for references in all policies
    referencing_rules: list[str] = []
    try:
        policies = client.get_all(_DFW_POLICIES_BASE)
        for policy in policies:
            policy_id = policy.get("id", "")
            if not policy_id:
                continue
            rules = client.get_all(f"{_DFW_POLICIES_BASE}/{policy_id}/rules")
            for rule in rules:
                sources = rule.get("source_groups", [])
                destinations = rule.get("destination_groups", [])
                if group_path in sources or group_path in destinations:
                    referencing_rules.append(
                        f"{policy_id}/{rule.get('id', 'unknown')}"
                    )
    except Exception as exc:
        _log.warning("Could not fully check group references: %s", exc)

    if referencing_rules:
        raise ValueError(
            f"Cannot delete group '{group_id}': referenced by {len(referencing_rules)} "
            f"DFW rule(s): {referencing_rules}. Remove the references first."
        )

    client.delete(f"{_GROUPS_BASE}/{group_id}")
    _log.info("Deleted security group: %s", group_id)
    return {"status": "deleted", "message": f"Security group '{group_id}' deleted."}
