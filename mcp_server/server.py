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

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from vmware_policy import vmware_tool

from vmware_nsx_security.config import load_config
from vmware_nsx_security.connection import ConnectionManager
from vmware_nsx_security.notify.audit import AuditLogger

logger = logging.getLogger(__name__)
_audit = AuditLogger()

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

_conn_mgr: ConnectionManager | None = None


def _get_connection(target: str | None = None) -> Any:
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
def list_dfw_policies(target: str | None = None) -> list[dict]:
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
        return [{"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}]


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_dfw_policy(policy_id: str, target: str | None = None) -> dict:
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_dfw_rules(policy_id: str, target: str | None = None) -> list[dict]:
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
        return [{"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}]


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_dfw_rule_stats(
    policy_id: str,
    rule_id: str,
    target: str | None = None,
) -> dict:
    """[READ] Get packet/byte hit-count statistics for a DFW rule.

    Returns packet_count, byte_count, session_count, and population_count
    (number of hosts where the rule is realised).

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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


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
    target: str | None = None,
) -> dict:
    """[WRITE] Create a new DFW security policy.

    Args:
        policy_id: Unique policy ID (alphanumeric, hyphens, underscores).
        display_name: Human-readable policy name.
        category: Policy category — Emergency, Infrastructure, Environment,
            or Application (default: Application).
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def update_dfw_policy(
    policy_id: str,
    display_name: str | None = None,
    description: str | None = None,
    sequence_number: int | None = None,
    stateful: bool | None = None,
    target: str | None = None,
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_dfw_policy(policy_id: str, target: str | None = None) -> dict:
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


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
    target: str | None = None,
) -> dict:
    """[WRITE] Create a DFW rule under the specified policy.

    Args:
        policy_id: Parent policy identifier.
        rule_id: Unique rule identifier within the policy.
        display_name: Human-readable rule name.
        action: Firewall action — ALLOW, DROP, REJECT, or
            JUMP_TO_APPLICATION (default: ALLOW).
        sources: List of source group paths. Use ['ANY'] for any source
            (default: ANY).
        destinations: List of destination group paths. Use ['ANY'] for any
            destination (default: ANY).
        services: List of service paths. Use ['ANY'] for all services
            (default: ANY).
        scope: List of scope paths (groups/segments) limiting where the
            rule is applied.
        direction: Traffic direction — IN, OUT, or IN_OUT (default: IN_OUT).
        ip_protocol: IP version — IPV4, IPV6, or IPV4_IPV6 (default: IPV4_IPV6).
        logged: Log matched traffic (default: False).
        disabled: Create the rule in disabled state (default: False).
        sequence_number: Rule priority within the policy (default: 10).
        description: Optional description.
        target: Optional NSX Manager target name from config.
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def update_dfw_rule(
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
    target: str | None = None,
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_dfw_rule(policy_id: str, rule_id: str, target: str | None = None) -> dict:
    """[WRITE] Delete a DFW rule from a policy.

    Args:
        policy_id: Parent policy identifier.
        rule_id: ID of the rule to delete.
        target: Optional NSX Manager target name from config.
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


# ═══════════════════════════════════════════════════════════════════════════════
# READ-ONLY: Security Groups
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_groups(target: str | None = None) -> list[dict]:
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
        return [{"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}]


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_group(group_id: str, target: str | None = None) -> dict:
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


# ═══════════════════════════════════════════════════════════════════════════════
# WRITE: Security Groups
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def create_group(
    group_id: str,
    display_name: str,
    description: str = "",
    tag_scope: str | None = None,
    tag_value: str | None = None,
    ip_addresses: list[str] | None = None,
    segment_paths: list[str] | None = None,
    target: str | None = None,
) -> dict:
    """[WRITE] Create an NSX security group with optional membership criteria.

    Membership criteria are ANDed together when multiple are provided:
    - tag_scope / tag_value: include VMs matching the NSX tag
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_group(group_id: str, target: str | None = None) -> dict:
    """[WRITE] Delete an NSX security group.

    Raises ValueError if the group is referenced by any DFW policy rule
    as a source or destination group.

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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


# ═══════════════════════════════════════════════════════════════════════════════
# READ-ONLY: VM Tags
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_vm_tags(vm_display_name: str, target: str | None = None) -> dict:
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


# ═══════════════════════════════════════════════════════════════════════════════
# WRITE: VM Tags
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def apply_vm_tag(
    vm_id: str,
    tag_scope: str,
    tag_value: str,
    target: str | None = None,
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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


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
    target: str | None = None,
) -> dict:
    """[WRITE] Run a Traceflow to trace a packet's path through the NSX overlay.

    Injects a synthetic probe packet from the source logical port and
    returns hop-by-hop observations including DFW rule hits and drop reasons.

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
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_traceflow_result(traceflow_id: str, target: str | None = None) -> dict:
    """[READ] Get the current status and observations of an existing Traceflow.

    Use this to check a previously initiated traceflow without waiting.

    Args:
        traceflow_id: Traceflow ID from a previous run_traceflow call.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.traceflow import get_traceflow_result as _fn

        client = _get_connection(target)
        return _fn(client, traceflow_id)
    except Exception as e:
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


# ═══════════════════════════════════════════════════════════════════════════════
# READ-ONLY: IDPS
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_idps_profiles(target: str | None = None) -> list[dict]:
    """[READ] List all IDPS profiles configured in NSX.

    Returns each profile's id, display_name, severity, criteria,
    and count of overridden signatures.

    Args:
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.idps import list_idps_profiles as _fn

        client = _get_connection(target)
        return _fn(client)
    except Exception as e:
        return [{"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}]


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_idps_status(target: str | None = None) -> dict:
    """[READ] Get the IDPS engine status across all transport nodes.

    Returns global_status (ENABLED/DISABLED), signature_version,
    last_signature_update, and per-node status counts.

    Args:
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.idps import get_idps_status as _fn

        client = _get_connection(target)
        return _fn(client)
    except Exception as e:
        return {"error": str(e), "hint": "Run 'vmware-nsx-security doctor' to verify connectivity."}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server using stdio transport."""
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
