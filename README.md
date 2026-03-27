# VMware NSX Security

VMware NSX DFW microsegmentation and security MCP skill — 20 tools for distributed firewall policies/rules, security groups, VM tags, Traceflow packet tracing, and IDPS.

> **Companion skills**: [vmware-nsx](https://github.com/zw008/VMware-NSX) (networking), [vmware-aiops](https://github.com/zw008/VMware-AIops) (VM lifecycle), [vmware-monitor](https://github.com/zw008/VMware-Monitor) (monitoring)

## Quick Start

```bash
uv tool install vmware-nsx-security

mkdir -p ~/.vmware-nsx-security
cp config.example.yaml ~/.vmware-nsx-security/config.yaml
# Edit config.yaml with your NSX Manager host

echo "VMWARE_NSX_SECURITY_NSX_PROD_PASSWORD=your_password" > ~/.vmware-nsx-security/.env
chmod 600 ~/.vmware-nsx-security/.env

vmware-nsx-security doctor
```

## What It Does

| Category | Tools |
|----------|-------|
| DFW Policy | list, get, create, update, delete, list rules |
| DFW Rules | create, update, delete, stats |
| Security Groups | list, get, create, delete |
| VM Tags | list tags, apply tag |
| Traceflow | run trace, get result |
| IDPS | list profiles, engine status |

**Total: 20 MCP tools** (10 read-only + 10 write)

## MCP Server Setup

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "vmware-nsx-security": {
      "command": "vmware-nsx-security-mcp",
      "env": {
        "VMWARE_NSX_SECURITY_CONFIG": "~/.vmware-nsx-security/config.yaml"
      }
    }
  }
}
```

## Common Workflows

### Microsegment an Application

```bash
# 1. Create groups by tag
vmware-nsx-security group create web-vms --name "Web VMs" --tag-scope tier --tag-value web
vmware-nsx-security group create app-vms --name "App VMs" --tag-scope tier --tag-value app

# 2. Create DFW policy
vmware-nsx-security policy create web-app-policy --name "Web to App" --category Application
```

### Tag a VM

```bash
# Find VM and its external ID
vmware-nsx-security tag list my-vm-01

# Apply tag using the external ID
vmware-nsx-security tag apply <external-id> --scope tier --value web
```

### Trace a Packet

```bash
vmware-nsx-security traceflow run <src-lport-id> \
  --src-ip 10.0.1.5 --dst-ip 10.0.2.10 --proto TCP --dst-port 443
```

## Safety

- **Dependency checks**: Cannot delete a policy with active rules, or a group referenced by DFW rules
- **Audit logging**: All write ops logged to `~/.vmware-nsx-security/audit.log`
- **Input validation**: IDs validated; all API text sanitized against prompt injection
- **Dry-run mode**: All CLI write commands support `--dry-run`
- **Credential safety**: Passwords only from env vars, never in config files

### Companion Skills

| Skill | Scope | Tools | Install |
|-------|-------|:-----:|---------|
| **[vmware-aiops](https://github.com/zw008/VMware-AIops)** ⭐ entry point | VM lifecycle, deployment, guest ops, clusters | 31 | `uv tool install vmware-aiops` |
| **[vmware-monitor](https://github.com/zw008/VMware-Monitor)** | Read-only monitoring, alarms, events, VM info | 8 | `uv tool install vmware-monitor` |
| **[vmware-nsx](https://github.com/zw008/VMware-NSX)** | NSX networking: segments, gateways, NAT, IPAM | 31 | `uv tool install vmware-nsx-mgmt` |
| **[vmware-storage](https://github.com/zw008/VMware-Storage)** | Datastores, iSCSI, vSAN | 11 | `uv tool install vmware-storage` |
| **[vmware-vks](https://github.com/zw008/VMware-VKS)** | Tanzu Namespaces, TKC cluster lifecycle | 20 | `uv tool install vmware-vks` |
| **[vmware-aria](https://github.com/zw008/VMware-Aria)** | Aria Ops metrics, alerts, capacity planning | 18 | `uv tool install vmware-aria` |

## License

MIT
