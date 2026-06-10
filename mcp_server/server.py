"""MCP server wrapping VMware NSX Security operations.

This module exposes VMware NSX DFW microsegmentation and security tools
via the Model Context Protocol (MCP) using stdio transport.  Each
``@mcp.tool()`` function delegates to the corresponding function in the
``vmware_nsx_security`` package.

Tool categories
---------------
* **Read-only** (no side effects): list_dfw_policies, get_dfw_policy,
  list_dfw_rules, list_groups, get_group, list_vm_tags,
  get_traceflow_result, list_idps_profiles, get_idps_status,
  get_dfw_rule_stats

* **Write** (mutate state): create_dfw_policy, update_dfw_policy,
  delete_dfw_policy, create_dfw_rule, update_dfw_rule, delete_dfw_rule,
  create_group, delete_group, apply_vm_tag, run_traceflow
  — should be gated by the AI agent's confirmation flow.

Security considerations
-----------------------
* **Credential handling**: Credentials are loaded from environment
  variables / ``.env`` file — never passed via MCP messages.
* **Transport**: Uses stdio transport (local only); no network listener.
* **Destructive ops**: Delete operations check for active references
  before proceeding and raise ValueError if unsafe.

For NSX networking (segments, gateways, NAT) use vmware-nsx.
For VM operations use vmware-aiops.
"""


import logging
import os
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from vmware_policy import vmware_tool

from vmware_policy import sanitize
from vmware_nsx_security.config import load_config
from vmware_nsx_security.connection import ConnectionManager
from vmware_nsx_security.notify.audit import AuditLogger

logger = logging.getLogger(__name__)
_audit = AuditLogger()

_DOCTOR_HINT = "Run 'vmware-nsx-security doctor' to verify connectivity."


def _safe_error(exc: Exception, tool: str) -> str:
    """Return an agent-safe error string; log full detail server-side only.

    Raw exception text from NSX can carry response bodies, internal paths, or
    host:port pairs. We log the full traceback to stderr (operator-visible) and
    return only a control-char-stripped, length-capped message to the agent.
    ``ValueError`` is treated as an intentional, user-facing validation message
    (e.g. "policy has active rules"); other exceptions get a generic message.
    """
    logger.error("Tool %s failed", tool, exc_info=True)
    if isinstance(exc, (ValueError, FileNotFoundError, KeyError)):
        return sanitize(str(exc), 300)
    return f"{type(exc).__name__}: operation failed."

mcp = FastMCP(
    "vmware-nsx-security",
    instructions=(
        "VMware NSX DFW microsegmentation and security operations. "
        "Manage distributed firewall policies and rules, security groups, "
        "VM NSX tags, run traceflow packet traces, and query IDPS status. "
        "For NSX networking (segments, gateways, NAT, routing), use vmware-nsx. "
        "For VM lifecycle operations, use vmware-aiops. "
        "For vSphere monitoring, use vmware-monitor."
    ),
)

# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

_conn_mgr: Optional[ConnectionManager] = None


def _get_connection(target: Optional[str] = None) -> Any:
    """Return an NsxClient, lazily initialising the connection manager."""
    global _conn_mgr  # noqa: PLW0603
    if _conn_mgr is None:
        config_path_str = os.environ.get("VMWARE_NSX_SECURITY_CONFIG")
        config_path = Path(config_path_str) if config_path_str else None
        config = load_config(config_path)
        _conn_mgr = ConnectionManager(config)
    return _conn_mgr.connect(target)


# ═══════════════════════════════════════════════════════════════════════════════
# READ-ONLY: DFW Policy
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_dfw_policies(target: Optional[str] = None) -> list[dict]:
    """[READ] List all DFW security policies in the default domain.

    Returns each policy's id, display_name, category, sequence_number,
    stateful flag, and rule count.

    Args:
        target: Optional NSX Manager target name from config. Uses default if omitted.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import list_dfw_policies as _fn

        client = _get_connection(target)
        return _fn(client)
    except Exception as e:
        return [{"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}]


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_dfw_policy(policy_id: str, target: Optional[str] = None) -> dict:
    """[READ] Get full details of a single DFW security policy.

    Args:
        policy_id: Policy identifier (e.g. 'app-tier-policy').
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import get_dfw_policy as _fn

        client = _get_connection(target)
        return _fn(client, policy_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_dfw_rules(policy_id: str, target: Optional[str] = None) -> list[dict]:
    """[READ] List all rules in a DFW security policy.

    Returns each rule's id, display_name, action, sources, destinations,
    services, direction, disabled flag, and sequence number.

    Args:
        policy_id: Parent policy identifier.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import list_dfw_rules as _fn

        client = _get_connection(target)
        return _fn(client, policy_id)
    except Exception as e:
        return [{"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}]


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_dfw_rule_stats(
    policy_id: str,
    rule_id: str,
    target: Optional[str] = None,
) -> dict:
    """[READ] Get packet/byte hit-count statistics for a DFW rule.

    Returns packet_count, byte_count, session_count, hit_count, and
    popularity_index (real NSX RuleStatistics fields).

    Args:
        policy_id: Parent policy identifier.
        rule_id: Rule identifier.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_rules import get_dfw_rule_stats as _fn

        client = _get_connection(target)
        return _fn(client, policy_id, rule_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ═══════════════════════════════════════════════════════════════════════════════
# WRITE: DFW Policy
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def create_dfw_policy(
    policy_id: str,
    display_name: str,
    category: str = "Application",
    sequence_number: int = 10,
    stateful: bool = True,
    description: str = "",
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Create a new DFW security policy.

    Args:
        policy_id: Unique policy ID (alphanumeric, hyphens, underscores).
        display_name: Human-readable policy name.
        category: Policy category — Ethernet, Emergency, Infrastructure,
            Environment, or Application (default: Application). Controls
            DFW evaluation order (Ethernet first, Application last).
        sequence_number: Priority order; lower number = higher priority (default: 10).
        stateful: Whether to track connection state (default: True).
        description: Optional description.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import create_dfw_policy as _fn

        client = _get_connection(target)
        result = _fn(
            client, policy_id, display_name,
            category=category, sequence_number=sequence_number,
            stateful=stateful, description=description,
        )
        _audit.log(
            target=target or "default",
            operation="create_dfw_policy",
            resource=policy_id,
            parameters={"display_name": display_name, "category": category},
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def update_dfw_policy(
    policy_id: str,
    display_name: Optional[str] = None,
    description: Optional[str] = None,
    sequence_number: Optional[int] = None,
    stateful: Optional[bool] = None,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Partially update a DFW security policy (PATCH — only provided fields change).

    Args:
        policy_id: ID of the policy to update.
        display_name: New display name (optional).
        description: New description (optional).
        sequence_number: New sequence number (optional).
        stateful: New stateful flag (optional).
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import update_dfw_policy as _fn

        client = _get_connection(target)
        result = _fn(
            client, policy_id,
            display_name=display_name, description=description,
            sequence_number=sequence_number, stateful=stateful,
        )
        _audit.log(
            target=target or "default",
            operation="update_dfw_policy",
            resource=policy_id,
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_dfw_policy(policy_id: str, target: Optional[str] = None) -> dict:
    """[WRITE] Delete a DFW security policy.

    Raises ValueError if the policy still contains active rules.
    Delete all rules in the policy first before deleting the policy itself.

    Args:
        policy_id: ID of the policy to delete.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import delete_dfw_policy as _fn

        client = _get_connection(target)
        result = _fn(client, policy_id)
        _audit.log(
            target=target or "default",
            operation="delete_dfw_policy",
            resource=policy_id,
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ═══════════════════════════════════════════════════════════════════════════════
# WRITE: DFW Rules
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def create_dfw_rule(
    policy_id: str,
    rule_id: str,
    display_name: str,
    action: str = "ALLOW",
    sources: Optional[list[str]] = None,
    destinations: Optional[list[str]] = None,
    services: Optional[list[str]] = None,
    scope: Optional[list[str]] = None,
    direction: str = "IN_OUT",
    ip_protocol: str = "IPV4_IPV6",
    logged: bool = False,
    disabled: bool = False,
    sequence_number: int = 10,
    description: str = "",
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Create a firewall rule under an existing DFW security policy.

    Creates via PUT, so calling again with the same rule_id replaces that
    rule's definition. The rule is enforced on the NSX data plane
    immediately unless disabled=True. Pick the policy_id with
    list_dfw_policies first; to change selected fields of an existing rule
    prefer update_dfw_rule, and to remove one use delete_dfw_rule. Calls
    are pre-checked by the vmware-policy engine (risk level: medium) and
    audited to ~/.vmware/audit.db.

    Returns the created rule dict from the NSX API (id, path, action,
    sequence_number, ...). On failure returns {"error", "hint"}; an
    invalid action/direction/ip_protocol returns an error listing the
    valid values.

    Args:
        policy_id: Parent policy ID (alphanumeric and hyphens), as
            returned by list_dfw_policies.
        rule_id: Unique rule ID within the policy (alphanumeric and
            hyphens). Reusing an existing ID overwrites that rule.
        display_name: Human-readable rule name.
        action: Firewall action — ALLOW, DROP, REJECT, or
            JUMP_TO_APPLICATION (default: ALLOW). JUMP_TO_APPLICATION is
            only valid in policies whose category is Environment.
        sources: Source group policy paths, e.g.
            ['/infra/domains/default/groups/web']. Use ['ANY'] or omit
            for any source (default: ANY).
        destinations: Destination group policy paths, same format as
            sources. Use ['ANY'] or omit for any destination (default: ANY).
        services: Service policy paths, e.g. ['/infra/services/HTTPS'].
            Use ['ANY'] or omit for all services (default: ANY).
        scope: Applied-to group/segment paths limiting where the rule is
            enforced. Omit to apply to the entire DFW.
        direction: Traffic direction — IN, OUT, or IN_OUT (default: IN_OUT).
        ip_protocol: IP version — IPV4, IPV6, or IPV4_IPV6 (default: IPV4_IPV6).
        logged: Log matched traffic (default: False).
        disabled: Create the rule disabled so it is not enforced
            (default: False).
        sequence_number: Rule priority within the policy; lower values
            match first (default: 10).
        description: Optional free-text description.
        target: Optional NSX Manager target name from config. Uses the
            default target if omitted.
    """
    try:
        from vmware_nsx_security.ops.dfw_rules import create_dfw_rule as _fn

        client = _get_connection(target)
        result = _fn(
            client, policy_id, rule_id, display_name,
            action=action, sources=sources, destinations=destinations,
            services=services, scope=scope, direction=direction,
            ip_protocol=ip_protocol, logged=logged, disabled=disabled,
            sequence_number=sequence_number, description=description,
        )
        _audit.log(
            target=target or "default",
            operation="create_dfw_rule",
            resource=f"{policy_id}/{rule_id}",
            parameters={"action": action, "display_name": display_name},
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def update_dfw_rule(
    policy_id: str,
    rule_id: str,
    display_name: Optional[str] = None,
    action: Optional[str] = None,
    sources: Optional[list[str]] = None,
    destinations: Optional[list[str]] = None,
    services: Optional[list[str]] = None,
    logged: Optional[bool] = None,
    disabled: Optional[bool] = None,
    sequence_number: Optional[int] = None,
    description: Optional[str] = None,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Partially update a DFW rule (PATCH — only provided fields change).

    Args:
        policy_id: Parent policy identifier.
        rule_id: Rule identifier to update.
        display_name: New display name (optional).
        action: New firewall action (optional).
        sources: New source groups (optional).
        destinations: New destination groups (optional).
        services: New services (optional).
        logged: New logged flag (optional).
        disabled: New disabled flag (optional).
        sequence_number: New sequence number (optional).
        description: New description (optional).
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_rules import update_dfw_rule as _fn

        client = _get_connection(target)
        result = _fn(
            client, policy_id, rule_id,
            display_name=display_name, action=action,
            sources=sources, destinations=destinations,
            services=services, logged=logged, disabled=disabled,
            sequence_number=sequence_number, description=description,
        )
        _audit.log(
            target=target or "default",
            operation="update_dfw_rule",
            resource=f"{policy_id}/{rule_id}",
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_dfw_rule(policy_id: str, rule_id: str, target: Optional[str] = None) -> dict:
    """[WRITE] Permanently delete one DFW rule from its parent security policy.

    Deletion is irreversible and takes effect immediately on the NSX data
    plane: traffic the rule matched falls through to lower-priority rules
    or the policy's default action. Confirm the rule_id with
    list_dfw_rules and check recent hits with get_dfw_rule_stats before
    deleting. To remove an entire policy use delete_dfw_policy (it refuses
    while rules remain); this tool deletes a single rule without that
    guard. Calls are pre-checked by the vmware-policy engine (risk level:
    high) and audited to ~/.vmware/audit.db; the CLI equivalent
    additionally requires double confirmation.

    Returns {"status": "deleted", "message": ...} on success, or
    {"error", "hint"} on failure (e.g. rule not found, connectivity).

    Args:
        policy_id: ID of the parent security policy (alphanumeric and
            hyphens), as returned by list_dfw_policies.
        rule_id: ID of the rule to delete within that policy, as returned
            by list_dfw_rules.
        target: Optional NSX Manager target name from config. Uses the
            default target if omitted.
    """
    try:
        from vmware_nsx_security.ops.dfw_rules import delete_dfw_rule as _fn

        client = _get_connection(target)
        result = _fn(client, policy_id, rule_id)
        _audit.log(
            target=target or "default",
            operation="delete_dfw_rule",
            resource=f"{policy_id}/{rule_id}",
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ═══════════════════════════════════════════════════════════════════════════════
# READ-ONLY: Security Groups
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_groups(target: Optional[str] = None) -> list[dict]:
    """[READ] List all NSX security groups in the default domain.

    Returns each group's id, display_name, description, and expression count.

    Args:
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import list_groups as _fn

        client = _get_connection(target)
        return _fn(client)
    except Exception as e:
        return [{"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}]


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_group(group_id: str, target: Optional[str] = None) -> dict:
    """[READ] Get details of a security group including membership criteria and effective members.

    Returns expression rules and up to 50 effective VirtualMachine members.

    Args:
        group_id: Group identifier (e.g. 'web-tier-vms').
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import get_group as _fn

        client = _get_connection(target)
        return _fn(client, group_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ═══════════════════════════════════════════════════════════════════════════════
# WRITE: Security Groups
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def create_group(
    group_id: str,
    display_name: str,
    description: str = "",
    tag_scope: Optional[str] = None,
    tag_value: Optional[str] = None,
    ip_addresses: Optional[list[str]] = None,
    segment_paths: Optional[list[str]] = None,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Create an NSX security group with optional membership criteria.

    Multiple criteria are ORed together (NSX only permits AND between
    same-member-type Conditions, so heterogeneous expression types must
    join with OR):
    - tag_scope / tag_value: include VMs matching the NSX tag
      (Condition with pipe-delimited value "scope|tag")
    - ip_addresses: include specific IP addresses or CIDRs
    - segment_paths: include all VMs on specified segments

    Args:
        group_id: Unique group identifier (alphanumeric, hyphens, underscores).
        display_name: Human-readable group name.
        description: Optional description.
        tag_scope: NSX tag scope for VM membership (e.g. 'env').
        tag_value: NSX tag value for VM membership (e.g. 'production').
        ip_addresses: List of IP addresses or CIDRs (e.g. ['10.0.1.0/24']).
        segment_paths: List of NSX segment policy paths.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import create_group as _fn

        client = _get_connection(target)
        result = _fn(
            client, group_id, display_name,
            description=description,
            tag_scope=tag_scope, tag_value=tag_value,
            ip_addresses=ip_addresses, segment_paths=segment_paths,
        )
        _audit.log(
            target=target or "default",
            operation="create_group",
            resource=group_id,
            parameters={"display_name": display_name},
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_group(group_id: str, target: Optional[str] = None) -> dict:
    """[WRITE] Delete an NSX security group.

    Refuses deletion if the group is referenced by any DFW rule (as
    source, destination, or applied-to scope) or by a policy-level
    scope, or if the reference scan itself fails.

    Args:
        group_id: ID of the group to delete.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import delete_group as _fn

        client = _get_connection(target)
        result = _fn(client, group_id)
        _audit.log(
            target=target or "default",
            operation="delete_group",
            resource=group_id,
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ═══════════════════════════════════════════════════════════════════════════════
# READ-ONLY: VM Tags
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_vm_tags(vm_display_name: str, target: Optional[str] = None) -> dict:
    """[READ] List all NSX tags applied to a virtual machine.

    Looks up the VM by display name and returns all scope/value tag pairs.
    Raises KeyError if no VM is found, ValueError if multiple VMs match.

    Args:
        vm_display_name: Display name of the virtual machine.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.tags import list_vm_tags as _fn

        client = _get_connection(target)
        return _fn(client, vm_display_name)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ═══════════════════════════════════════════════════════════════════════════════
# WRITE: VM Tags
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def apply_vm_tag(
    vm_id: str,
    tag_scope: str,
    tag_value: str,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Apply an NSX tag to a virtual machine.

    Existing tags on the VM are preserved — this operation is additive.
    Use list_vm_tags to get the vm_id (external_id) first.

    Args:
        vm_id: VM external ID (fabric UUID, obtainable from list_vm_tags).
        tag_scope: Tag scope string (e.g. 'env', 'tier', 'owner').
        tag_value: Tag value string (e.g. 'production', 'web').
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.tags import apply_vm_tag as _fn

        client = _get_connection(target)
        result = _fn(client, vm_id, tag_scope, tag_value)
        _audit.log(
            target=target or "default",
            operation="apply_vm_tag",
            resource=vm_id,
            parameters={"scope": tag_scope, "tag": tag_value},
            result="ok",
        )
        return result
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ═══════════════════════════════════════════════════════════════════════════════
# Traceflow
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def run_traceflow(
    src_lport_id: str,
    src_ip: str,
    dst_ip: str,
    protocol: str = "TCP",
    dst_port: int = 80,
    src_port: int = 1234,
    ttl: int = 64,
    timeout_seconds: int = 20,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Run a Traceflow to trace a packet's path through the NSX overlay.

    Injects a synthetic probe packet from the source logical port and
    returns hop-by-hop observations including DFW rule hits and drop
    reasons. The result reports operation_state (IN_PROGRESS / FINISHED /
    FAILED) and observations discriminated by resource_type (e.g.
    TraceflowObservationForwarded, TraceflowObservationDroppedLogical —
    Dropped* entries carry reason and acl_rule_id).

    Args:
        src_lport_id: Source logical port ID (attachment UUID of the VM NIC).
        src_ip: Source IP address for the probe packet.
        dst_ip: Destination IP address.
        protocol: IP protocol — TCP, UDP, or ICMP (default: TCP).
        dst_port: Destination port for TCP/UDP probes (default: 80).
        src_port: Source port for TCP/UDP probes (default: 1234).
        ttl: IP TTL value (default: 64).
        timeout_seconds: Maximum seconds to wait for completion (default: 20).
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.traceflow import run_traceflow as _fn

        client = _get_connection(target)
        return _fn(
            client, src_lport_id, src_ip, dst_ip,
            protocol=protocol, dst_port=dst_port,
            src_port=src_port, ttl=ttl, timeout_seconds=timeout_seconds,
        )
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_traceflow_result(traceflow_id: str, target: Optional[str] = None) -> dict:
    """[READ] Get the current state and observations of an existing Traceflow.

    Use this to check a previously initiated traceflow without waiting.
    Returns operation_state (IN_PROGRESS / FINISHED / FAILED) and
    observations discriminated by resource_type; Dropped* observations
    carry reason and acl_rule_id.

    Args:
        traceflow_id: Traceflow ID from a previous run_traceflow call.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.traceflow import get_traceflow_result as _fn

        client = _get_connection(target)
        return _fn(client, traceflow_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ═══════════════════════════════════════════════════════════════════════════════
# READ-ONLY: IDPS
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_idps_profiles(target: Optional[str] = None) -> list[dict]:
    """[READ] List all IDPS profiles configured in NSX.

    Returns each profile's id, display_name, profile_severity
    (comma-joined list), criteria (filter_name/filter_value pairs such
    as ATTACK_TYPE or CVSS filters), and overridden signature count.

    Args:
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.idps import list_idps_profiles as _fn

        client = _get_connection(target)
        return _fn(client)
    except Exception as e:
        return [{"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}]


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_idps_status(target: Optional[str] = None) -> dict:
    """[READ] Get IDPS signature status and global IDS settings.

    Returns 'signature_status' (scalar fields of the signature bundle
    status resource, e.g. version/update state — field names vary by NSX
    release) and 'settings' (auto_update, ids_events_to_syslog).

    Args:
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.idps import get_idps_status as _fn

        client = _get_connection(target)
        return _fn(client)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server using stdio transport."""
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
