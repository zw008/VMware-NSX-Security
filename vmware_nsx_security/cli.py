"""CLI entry point for VMware NSX Security.

Provides DFW policy/rule management, security group operations, VM tag
management, traceflow, and IDPS queries with --dry-run preview and
double confirmation for destructive actions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from vmware_nsx_security.config import CONFIG_DIR
from vmware_nsx_security.notify.audit import AuditLogger

_audit = AuditLogger()

app = typer.Typer(
    name="vmware-nsx-security",
    help="VMware NSX DFW microsegmentation and security operations.",
    no_args_is_help=True,
)
console = Console()

# ─── Sub-command groups ──────────────────────────────────────────────────────

policy_app = typer.Typer(help="DFW security policy management: list, get, create, update, delete.")
rule_app = typer.Typer(help="DFW rule management: list, create, update, delete, stats.")
group_app = typer.Typer(help="Security group management: list, get, create, delete.")
tag_app = typer.Typer(help="VM NSX tag management: list, apply, remove.")
traceflow_app = typer.Typer(help="Traceflow packet tracing: run, get.")
idps_app = typer.Typer(help="IDPS: list profiles, check engine status.")

app.add_typer(policy_app, name="policy")
app.add_typer(rule_app, name="rule")
app.add_typer(group_app, name="group")
app.add_typer(tag_app, name="tag")
app.add_typer(traceflow_app, name="traceflow")
app.add_typer(idps_app, name="idps")

# ─── Type aliases ────────────────────────────────────────────────────────────

TargetOption = Annotated[
    str | None, typer.Option("--target", "-t", help="Target name from config")
]
ConfigOption = Annotated[
    Path | None, typer.Option("--config", "-c", help="Config file path")
]
DryRunOption = Annotated[
    bool, typer.Option("--dry-run", help="Print API calls without executing")
]


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _get_connection(target: str | None, config_path: Path | None = None):
    """Return (NsxClient, AppConfig)."""
    from vmware_nsx_security.config import load_config
    from vmware_nsx_security.connection import ConnectionManager

    cfg = load_config(config_path)
    mgr = ConnectionManager(cfg)
    name = target or cfg.default_target
    return mgr.connect(name), cfg


def _resolve_target(target: str | None) -> str:
    """Return display name for audit logs."""
    return target or "default"


def _dry_run_print(
    *,
    target: str,
    resource: str,
    operation: str,
    api_call: str,
    parameters: dict | None = None,
) -> None:
    """Print a dry-run preview of the API call that would be made."""
    console.print("\n[bold magenta][DRY-RUN] No changes will be made.[/]")
    console.print(f"[magenta]  Target:    {target}[/]")
    console.print(f"[magenta]  Resource:  {resource}[/]")
    console.print(f"[magenta]  Operation: {operation}[/]")
    console.print(f"[magenta]  API Call:  {api_call}[/]")
    if parameters:
        console.print(f"[magenta]  Params:    {json.dumps(parameters, indent=2)}[/]")
    console.print()


def _confirm_destructive(resource_type: str, resource_id: str) -> bool:
    """Double-confirmation prompt for destructive operations."""
    console.print(
        f"[bold red]WARNING:[/] This will permanently delete "
        f"{resource_type} '[bold]{resource_id}[/]'."
    )
    first = typer.confirm("Are you sure you want to proceed?", default=False)
    if not first:
        return False
    second = typer.confirm(
        f"Second confirmation: DELETE {resource_type} '{resource_id}'?",
        default=False,
    )
    return second


# ═══════════════════════════════════════════════════════════════════════════════
# DFW Policy commands
# ═══════════════════════════════════════════════════════════════════════════════


@policy_app.command("list")
def policy_list(
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """List all DFW security policies."""
    from vmware_nsx_security.ops.dfw_policy import list_dfw_policies

    client, _ = _get_connection(target, config)
    policies = list_dfw_policies(client)

    table = Table(title="DFW Security Policies")
    table.add_column("ID")
    table.add_column("Display Name")
    table.add_column("Category")
    table.add_column("Seq#", justify="right")
    table.add_column("Stateful")
    table.add_column("Rules", justify="right")

    for p in policies:
        table.add_row(
            p["id"],
            p["display_name"],
            p["category"],
            str(p["sequence_number"]),
            str(p["stateful"]),
            str(p["rule_count"]),
        )
    console.print(table)


@policy_app.command("get")
def policy_get(
    policy_id: str = typer.Argument(..., help="Policy ID"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Get details of a DFW security policy."""
    from vmware_nsx_security.ops.dfw_policy import get_dfw_policy

    client, _ = _get_connection(target, config)
    p = get_dfw_policy(client, policy_id)
    console.print_json(json.dumps(p))


@policy_app.command("create")
def policy_create(
    policy_id: str = typer.Argument(..., help="Policy ID"),
    display_name: str = typer.Option(..., "--name", help="Display name"),
    category: str = typer.Option("Application", "--category", help="Policy category"),
    sequence_number: int = typer.Option(10, "--seq", help="Sequence number"),
    description: str = typer.Option("", "--description", help="Description"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Create a DFW security policy."""
    from vmware_nsx_security.ops.dfw_policy import create_dfw_policy

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=policy_id,
            operation="create_dfw_policy",
            api_call=f"PUT /policy/api/v1/infra/domains/default/security-policies/{policy_id}",
            parameters={"display_name": display_name, "category": category, "sequence_number": sequence_number},
        )
        return

    client, _ = _get_connection(target, config)
    result = create_dfw_policy(
        client, policy_id, display_name,
        category=category, sequence_number=sequence_number, description=description,
    )
    _audit.log(target=t, operation="create_dfw_policy", resource=policy_id, result="ok")
    console.print(f"[green]Created DFW policy '{policy_id}'[/]")
    console.print_json(json.dumps(result))


@policy_app.command("delete")
def policy_delete(
    policy_id: str = typer.Argument(..., help="Policy ID to delete"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Delete a DFW security policy (checks for active rules first)."""
    from vmware_nsx_security.ops.dfw_policy import delete_dfw_policy

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=policy_id,
            operation="delete_dfw_policy",
            api_call=f"DELETE /policy/api/v1/infra/domains/default/security-policies/{policy_id}",
        )
        return

    if not _confirm_destructive("DFW policy", policy_id):
        console.print("Aborted.")
        raise typer.Exit(0)

    client, _ = _get_connection(target, config)
    result = delete_dfw_policy(client, policy_id)
    _audit.log(target=t, operation="delete_dfw_policy", resource=policy_id, result="ok")
    console.print(f"[green]{result['message']}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# DFW Rule commands
# ═══════════════════════════════════════════════════════════════════════════════


@rule_app.command("list")
def rule_list(
    policy_id: str = typer.Argument(..., help="Parent policy ID"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """List all rules in a DFW policy."""
    from vmware_nsx_security.ops.dfw_policy import list_dfw_rules

    client, _ = _get_connection(target, config)
    rules = list_dfw_rules(client, policy_id)

    table = Table(title=f"DFW Rules in Policy '{policy_id}'")
    table.add_column("ID")
    table.add_column("Display Name")
    table.add_column("Action")
    table.add_column("Direction")
    table.add_column("Disabled")
    table.add_column("Logged")

    for r in rules:
        table.add_row(
            r["id"],
            r["display_name"],
            r["action"],
            r["direction"],
            str(r["disabled"]),
            str(r["logged"]),
        )
    console.print(table)


@rule_app.command("stats")
def rule_stats(
    policy_id: str = typer.Argument(..., help="Parent policy ID"),
    rule_id: str = typer.Argument(..., help="Rule ID"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Get hit-count statistics for a DFW rule."""
    from vmware_nsx_security.ops.dfw_rules import get_dfw_rule_stats

    client, _ = _get_connection(target, config)
    stats = get_dfw_rule_stats(client, policy_id, rule_id)
    console.print_json(json.dumps(stats))


@rule_app.command("delete")
def rule_delete(
    policy_id: str = typer.Argument(..., help="Parent policy ID"),
    rule_id: str = typer.Argument(..., help="Rule ID to delete"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Delete a DFW rule."""
    from vmware_nsx_security.ops.dfw_rules import delete_dfw_rule

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=f"{policy_id}/{rule_id}",
            operation="delete_dfw_rule",
            api_call=f"DELETE ...security-policies/{policy_id}/rules/{rule_id}",
        )
        return

    if not _confirm_destructive("DFW rule", rule_id):
        console.print("Aborted.")
        raise typer.Exit(0)

    client, _ = _get_connection(target, config)
    result = delete_dfw_rule(client, policy_id, rule_id)
    _audit.log(target=t, operation="delete_dfw_rule", resource=f"{policy_id}/{rule_id}", result="ok")
    console.print(f"[green]{result['message']}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# Security Group commands
# ═══════════════════════════════════════════════════════════════════════════════


@group_app.command("list")
def group_list(
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """List all security groups."""
    from vmware_nsx_security.ops.security_group import list_groups

    client, _ = _get_connection(target, config)
    groups = list_groups(client)

    table = Table(title="Security Groups")
    table.add_column("ID")
    table.add_column("Display Name")
    table.add_column("Description")
    table.add_column("Expressions", justify="right")

    for g in groups:
        table.add_row(
            g["id"],
            g["display_name"],
            g["description"][:60],
            str(g["expression_count"]),
        )
    console.print(table)


@group_app.command("get")
def group_get(
    group_id: str = typer.Argument(..., help="Group ID"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Get details and members of a security group."""
    from vmware_nsx_security.ops.security_group import get_group

    client, _ = _get_connection(target, config)
    g = get_group(client, group_id)
    console.print_json(json.dumps(g))


@group_app.command("delete")
def group_delete(
    group_id: str = typer.Argument(..., help="Group ID to delete"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Delete a security group (checks DFW policy references first)."""
    from vmware_nsx_security.ops.security_group import delete_group

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=group_id,
            operation="delete_group",
            api_call=f"DELETE /policy/api/v1/infra/domains/default/groups/{group_id}",
        )
        return

    if not _confirm_destructive("security group", group_id):
        console.print("Aborted.")
        raise typer.Exit(0)

    client, _ = _get_connection(target, config)
    result = delete_group(client, group_id)
    _audit.log(target=t, operation="delete_group", resource=group_id, result="ok")
    console.print(f"[green]{result['message']}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# Tag commands
# ═══════════════════════════════════════════════════════════════════════════════


@tag_app.command("list")
def tag_list(
    vm_name: str = typer.Argument(..., help="VM display name"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """List NSX tags applied to a VM."""
    from vmware_nsx_security.ops.tags import list_vm_tags

    client, _ = _get_connection(target, config)
    result = list_vm_tags(client, vm_name)

    console.print(f"[bold]VM:[/] {result['display_name']}  [bold]ID:[/] {result['vm_id']}")
    table = Table(title="NSX Tags")
    table.add_column("Scope")
    table.add_column("Tag")
    for t_entry in result.get("tags", []):
        table.add_row(t_entry.get("scope", ""), t_entry.get("tag", ""))
    console.print(table)


@tag_app.command("apply")
def tag_apply(
    vm_id: str = typer.Argument(..., help="VM external ID"),
    scope: str = typer.Option(..., "--scope", help="Tag scope"),
    value: str = typer.Option(..., "--value", help="Tag value"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Apply an NSX tag to a VM."""
    from vmware_nsx_security.ops.tags import apply_vm_tag

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=vm_id,
            operation="apply_vm_tag",
            api_call="POST /api/v1/fabric/tags/tag?action=add_tag",
            parameters={"scope": scope, "tag": value},
        )
        return

    client, _ = _get_connection(target, config)
    result = apply_vm_tag(client, vm_id, scope, value)
    _audit.log(
        target=t, operation="apply_vm_tag", resource=vm_id,
        parameters={"scope": scope, "tag": value}, result="ok",
    )
    console.print(f"[green]Applied tag {scope}={value} to VM {vm_id}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# Traceflow commands
# ═══════════════════════════════════════════════════════════════════════════════


@traceflow_app.command("run")
def traceflow_run(
    src_lport: str = typer.Argument(..., help="Source logical port ID"),
    src_ip: str = typer.Option(..., "--src-ip", help="Source IP address"),
    dst_ip: str = typer.Option(..., "--dst-ip", help="Destination IP address"),
    protocol: str = typer.Option("TCP", "--proto", help="Protocol: TCP, UDP, or ICMP"),
    dst_port: int = typer.Option(80, "--dst-port", help="Destination port"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Run a Traceflow packet trace from a logical port."""
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client, _ = _get_connection(target, config)
    result = run_traceflow(client, src_lport, src_ip, dst_ip, protocol=protocol, dst_port=dst_port)
    console.print_json(json.dumps(result))


# ═══════════════════════════════════════════════════════════════════════════════
# IDPS commands
# ═══════════════════════════════════════════════════════════════════════════════


@idps_app.command("profiles")
def idps_profiles(
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """List IDPS profiles."""
    from vmware_nsx_security.ops.idps import list_idps_profiles

    client, _ = _get_connection(target, config)
    profiles = list_idps_profiles(client)

    table = Table(title="IDPS Profiles")
    table.add_column("ID")
    table.add_column("Display Name")
    table.add_column("Severity")
    table.add_column("Overridden Sigs", justify="right")

    for p in profiles:
        table.add_row(
            p["id"],
            p["display_name"],
            p["profile_severity"],
            str(p["overridden_signature_count"]),
        )
    console.print(table)


@idps_app.command("status")
def idps_status(
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Get IDPS engine status."""
    from vmware_nsx_security.ops.idps import get_idps_status

    client, _ = _get_connection(target, config)
    status = get_idps_status(client)
    console.print_json(json.dumps(status))


# ═══════════════════════════════════════════════════════════════════════════════
# Doctor
# ═══════════════════════════════════════════════════════════════════════════════


@app.command("doctor")
def doctor(
    skip_auth: bool = typer.Option(False, "--skip-auth", help="Skip authentication test"),
    config: ConfigOption = None,
) -> None:
    """Run pre-flight environment diagnostics."""
    from vmware_nsx_security.doctor import run_doctor

    ok = run_doctor(config_path=config, skip_auth=skip_auth)
    raise typer.Exit(0 if ok else 1)


if __name__ == "__main__":
    app()
