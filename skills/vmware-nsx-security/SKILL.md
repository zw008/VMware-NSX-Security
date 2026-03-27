---
name: vmware-nsx-security
description: >
  VMware NSX DFW microsegmentation and security operations: distributed firewall
  policies and rules, security groups, VM tags, Traceflow packet tracing, and IDPS.
  Use when user asks to "list firewall rules", "create a DFW policy", "create security group",
  "trace a packet", "check IDS status", "apply NSX tag to VM", or mentions
  NSX DFW/microsegmentation/security policy/zero-trust operations.
  For NSX networking (segments, gateways, NAT) use vmware-nsx,
  for VM operations use vmware-aiops.
installer:
  kind: uv
  package: vmware-nsx-security
metadata: {"openclaw":{"requires":{"env":["VMWARE_NSX_SECURITY_CONFIG"],"bins":["vmware-nsx-security"],"config":["~/.vmware-nsx-security/config.yaml"]},"primaryEnv":"VMWARE_NSX_SECURITY_CONFIG","homepage":"https://github.com/zw008/VMware-NSX-Security","emoji":"🔒","os":["macos","linux"]}}
---

# VMware NSX Security

VMware NSX DFW microsegmentation and security — 20 MCP tools for distributed firewall, security groups, VM tags, Traceflow, and IDPS.

> Domain-focused security skill for NSX-T / NSX 4.x Policy API.
> **Companion skills**: [vmware-nsx](https://github.com/zw008/VMware-NSX) (networking), [vmware-aiops](https://github.com/zw008/VMware-AIops) (VM lifecycle), [vmware-monitor](https://github.com/zw008/VMware-Monitor) (read-only monitoring).

## What This Skill Does

| Category | Tools | Count |
|----------|-------|:-----:|
| **DFW Policy** | list, get, create, update, delete, list rules | 6 |
| **DFW Rules** | create, update, delete, get stats | 4 |
| **Security Groups** | list, get, create, delete | 4 |
| **VM Tags** | list VM tags, apply tag | 2 |
| **Traceflow** | run trace, get result | 2 |
| **IDPS** | list profiles, get status | 2 |

**Total**: 20 tools (10 read-only + 10 write)

## Quick Install

```bash
uv tool install vmware-nsx-security
vmware-nsx-security doctor
```

## When to Use This Skill

- List, create, or modify DFW security policies and rules
- Create security groups based on VM tags, IP ranges, or segment membership
- Apply or list NSX tags on virtual machines
- Run Traceflow to trace a packet path and diagnose drop reasons
- Check IDPS profile configuration and engine status
- Implement zero-trust microsegmentation between application tiers

**Use companion skills for**:
- NSX segments, gateways, NAT, routing, IPAM → `vmware-nsx`
- VM lifecycle, deployment, guest ops → `vmware-aiops`
- vSphere inventory, health, alarms, events → `vmware-monitor`
- Storage: iSCSI, vSAN, datastores → `vmware-storage`
- Tanzu Kubernetes → `vmware-vks`

## Related Skills — Skill Routing

| User Intent | Recommended Skill |
|-------------|-------------------|
| NSX security: DFW rules, security groups, IDS/IPS | **vmware-nsx-security** ← this skill |
| NSX networking: segments, gateways, NAT, routing | **vmware-nsx** |
| Read-only vSphere monitoring, alarms, events | **vmware-monitor** |
| VM lifecycle, deployment, guest ops | **vmware-aiops** |
| Storage: iSCSI, vSAN, datastores | **vmware-storage** |
| Tanzu Kubernetes | **vmware-vks** |

## Common Workflows

### Implement App-Tier Microsegmentation

1. Create a security group for web VMs based on NSX tag:
   ```bash
   vmware-nsx-security group create web-vms --name "Web Tier VMs" --tag-scope tier --tag-value web
   ```
2. Create a security group for app VMs:
   ```bash
   vmware-nsx-security group create app-vms --name "App Tier VMs" --tag-scope tier --tag-value app
   ```
3. Create a DFW policy:
   ```bash
   vmware-nsx-security policy create app-microseg --name "App Microsegmentation" --category Application
   ```
4. List rules to verify (empty initially):
   ```bash
   vmware-nsx-security rule list app-microseg
   ```

### Apply NSX Tags to VMs

1. Find VM and its tags:
   ```bash
   vmware-nsx-security tag list my-web-vm-01
   ```
2. Get the VM external ID from the output, then apply tag:
   ```bash
   vmware-nsx-security tag apply <vm-external-id> --scope tier --value web
   ```

### Trace a Packet with Traceflow

1. Get source VM's logical port ID (from `vmware-nsx troubleshoot vm-segment`):
   ```bash
   vmware-nsx-security traceflow run <lport-id> --src-ip 10.0.1.5 --dst-ip 10.0.2.10 --proto TCP --dst-port 443
   ```
2. Check for DFW hits and drop reasons in the output.

### Check DFW Policy Hit Counts

```bash
vmware-nsx-security policy list
vmware-nsx-security rule list <policy-id>
vmware-nsx-security rule stats <policy-id> <rule-id>
```

### Multi-Target Operations

All commands accept `--target <name>` to operate against a specific NSX Manager:

```bash
# Default target
vmware-nsx-security policy list

# Specific target
vmware-nsx-security policy list --target nsx-prod
vmware-nsx-security group list --target nsx-lab
```

## MCP Tools (20)

All MCP tools accept an optional `target` parameter.

| Category | Tool | Type | Description |
|----------|------|:----:|-------------|
| DFW Policy | `list_dfw_policies` | Read | List all DFW security policies with category, sequence, and rule count |
| | `get_dfw_policy` | Read | Get policy details: category, stateful, locked, scope, tags |
| | `create_dfw_policy` | Write | Create a new DFW policy with category and sequence number |
| | `update_dfw_policy` | Write | Partial update: display_name, description, sequence_number, stateful |
| | `delete_dfw_policy` | Write | Delete policy — refuses if active rules exist |
| | `list_dfw_rules` | Read | List rules in a policy: action, sources, destinations, services |
| DFW Rules | `create_dfw_rule` | Write | Create rule with sources/destinations/services/action/scope |
| | `update_dfw_rule` | Write | Partial update rule fields |
| | `delete_dfw_rule` | Write | Delete a rule from a policy |
| | `get_dfw_rule_stats` | Read | Get packet/byte hit counts for a rule |
| Security Groups | `list_groups` | Read | List all security groups with expression count |
| | `get_group` | Read | Get group details: expression criteria + up to 50 effective VM members |
| | `create_group` | Write | Create group with tag/IP/segment membership criteria |
| | `delete_group` | Write | Delete group — refuses if referenced by DFW rules |
| VM Tags | `list_vm_tags` | Read | List NSX tags on a VM by display name |
| | `apply_vm_tag` | Write | Apply a scope/value tag to a VM (additive, preserves existing tags) |
| Traceflow | `run_traceflow` | Write | Inject probe packet and return hop-by-hop observations |
| | `get_traceflow_result` | Read | Check status/observations of an existing traceflow |
| IDPS | `list_idps_profiles` | Read | List IDPS profiles with severity and criteria |
| | `get_idps_status` | Read | Get IDPS engine status: enabled/disabled, signature version, per-node counts |

## CLI Quick Reference

```bash
# DFW Policy
vmware-nsx-security policy list [--target <name>]
vmware-nsx-security policy get <policy-id>
vmware-nsx-security policy create <id> --name "Display Name" --category Application [--dry-run]
vmware-nsx-security policy delete <id> [--dry-run]

# DFW Rules
vmware-nsx-security rule list <policy-id>
vmware-nsx-security rule stats <policy-id> <rule-id>
vmware-nsx-security rule delete <policy-id> <rule-id> [--dry-run]

# Security Groups
vmware-nsx-security group list
vmware-nsx-security group get <group-id>
vmware-nsx-security group delete <group-id> [--dry-run]

# Tags
vmware-nsx-security tag list <vm-display-name>
vmware-nsx-security tag apply <vm-external-id> --scope env --value production [--dry-run]

# Traceflow
vmware-nsx-security traceflow run <lport-id> --src-ip 10.0.1.5 --dst-ip 10.0.2.10

# IDPS
vmware-nsx-security idps profiles
vmware-nsx-security idps status

# Diagnostics
vmware-nsx-security doctor [--skip-auth]
```

## Troubleshooting

### "Cannot delete policy — active rules exist"

`delete_dfw_policy` checks for active rules before deleting. Use `vmware-nsx-security rule list <policy-id>` to see which rules need to be removed first. Then delete each rule individually before retrying the policy deletion.

### "Cannot delete group — referenced by DFW rules"

`delete_group` scans all policies for rules that reference the group in source_groups or destination_groups. Remove the group from those rules first (via `update_dfw_rule` replacing the group path with 'ANY' or another group), then retry.

### "No virtual machine found with display_name"

`list_vm_tags` looks up VMs by display name via the NSX fabric API. Common causes:
1. Display name mismatch — the name in NSX Manager may differ from vCenter. Check `vmware-monitor vm list` for the exact NSX fabric display name.
2. VM not registered — newly deployed VMs may take a minute to appear in the NSX fabric.
3. Multiple VMs with the same name — use `apply_vm_tag` with the specific external_id.

### Traceflow returns empty observations

1. Verify the `src_lport_id` is the correct logical port attachment UUID — not the segment port path. Get it from `vmware-nsx troubleshoot vm-segment <vm>`.
2. The source VM must be powered on and connected to an NSX overlay segment.
3. If the VM is on a VLAN-backed segment, Traceflow is not supported.
4. NSX Manager requires the transport node hosting the source VM to be reachable. Check `vmware-nsx health transport-nodes`.

### DFW rule stats show zero hits

A newly created rule will have zero hit counts until traffic matches it. If expected traffic still shows zero:
1. Confirm the rule is not disabled (`disabled: false` in `list_dfw_rules` output).
2. Check that source/destination group membership is correct using `get_group`.
3. Verify rule sequence number — a lower-sequence rule with ALLOW/DROP may be matching first.

### "Password not found" error

Password variable convention: `VMWARE_NSX_SECURITY_<TARGET_UPPER>_PASSWORD`
where hyphens are replaced by underscores. For target `nsx-prod`:
`VMWARE_NSX_SECURITY_NSX_PROD_PASSWORD`. Check `~/.vmware-nsx-security/.env`.

## Safety

- **Audit logging**: All write operations logged to `~/.vmware-nsx-security/audit.log` in JSON Lines format with timestamp, user, target, operation, parameters, and result
- **Dependency checks**: `delete_dfw_policy` checks for active rules; `delete_group` checks for DFW rule references — prevents accidental cascade failures
- **Input validation**: All IDs validated against safe character set (alphanumerics, hyphens, underscores, dots); all text fields sanitized to strip control characters
- **Dry-run mode**: CLI write commands support `--dry-run` to preview API calls without executing
- **Double confirmation**: CLI destructive operations (delete) require two separate confirmation prompts
- **Credential safety**: Passwords loaded only from environment variables (`.env` file), never from `config.yaml`
- **No networking changes**: Cannot modify segments, gateways, NAT, or routing — that scope belongs to `vmware-nsx`
- **Prompt injection defense**: All API-sourced strings passed through `_sanitize()` before inclusion in tool output

## Setup

```bash
uv tool install vmware-nsx-security
mkdir -p ~/.vmware-nsx-security
cp config.example.yaml ~/.vmware-nsx-security/config.yaml
# Edit config.yaml with your NSX Manager targets

echo "VMWARE_NSX_SECURITY_NSX_PROD_PASSWORD=your_password" > ~/.vmware-nsx-security/.env
chmod 600 ~/.vmware-nsx-security/.env

vmware-nsx-security doctor
```

> Full setup guide: see `references/setup-guide.md`

## Architecture

```
User (natural language)
  |
AI Agent (Claude Code / Goose / Cursor)
  | reads SKILL.md
vmware-nsx-security CLI or MCP server (stdio transport)
  | NSX Policy API (REST/JSON over HTTPS)
NSX Manager
  |
DFW Policies / Rules / Security Groups / Tags / IDPS
```

The MCP server uses stdio transport (local only, no network listener). All connections to NSX Manager use HTTPS on port 443.

## License

MIT — [github.com/zw008/VMware-NSX-Security](https://github.com/zw008/VMware-NSX-Security)
