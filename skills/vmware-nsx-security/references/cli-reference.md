# VMware NSX Security CLI Reference

## Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--target` | `-t` | NSX Manager target name from config (uses `default_target` if omitted) |
| `--config` | `-c` | Path to config file (overrides `VMWARE_NSX_SECURITY_CONFIG` env var) |
| `--dry-run` | | Preview API call without executing (write commands only) |
| `--help` | | Show help for any command |

---

## `policy` — DFW Policy Management

### `policy list`
List all DFW security policies.

```bash
vmware-nsx-security policy list [--target <name>]
```

Output columns: ID, Display Name, Category, Seq#, Stateful, Rules

### `policy get`
Get full details of a DFW policy.

```bash
vmware-nsx-security policy get <policy-id> [--target <name>]
```

### `policy create`
Create a new DFW security policy.

```bash
vmware-nsx-security policy create <policy-id> \
  --name "Display Name" \
  [--category Application|Emergency|Infrastructure|Environment] \
  [--seq <number>] \
  [--description "text"] \
  [--dry-run] \
  [--target <name>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--name` | required | Human-readable policy name |
| `--category` | Application | Policy evaluation category |
| `--seq` | 10 | Sequence number (lower = higher priority) |
| `--description` | "" | Optional description |

### `policy delete`
Delete a DFW policy (requires no active rules).

```bash
vmware-nsx-security policy delete <policy-id> [--dry-run] [--target <name>]
```

Prompts for double confirmation. Fails if the policy contains rules.

---

## `rule` — DFW Rule Management

### `rule list`
List all rules in a policy.

```bash
vmware-nsx-security rule list <policy-id> [--target <name>]
```

Output columns: ID, Display Name, Action, Direction, Disabled, Logged

### `rule stats`
Get packet/byte hit-count statistics for a rule.

```bash
vmware-nsx-security rule stats <policy-id> <rule-id> [--target <name>]
```

### `rule delete`
Delete a DFW rule.

```bash
vmware-nsx-security rule delete <policy-id> <rule-id> [--dry-run] [--target <name>]
```

Prompts for double confirmation.

---

## `group` — Security Group Management

### `group list`
List all security groups.

```bash
vmware-nsx-security group list [--target <name>]
```

### `group get`
Get group details including membership criteria and effective VM members.

```bash
vmware-nsx-security group get <group-id> [--target <name>]
```

### `group delete`
Delete a security group (checks for DFW rule references first).

```bash
vmware-nsx-security group delete <group-id> [--dry-run] [--target <name>]
```

---

## `tag` — VM NSX Tag Management

### `tag list`
List NSX tags on a VM by display name.

```bash
vmware-nsx-security tag list <vm-display-name> [--target <name>]
```

### `tag apply`
Apply an NSX tag to a VM (by external ID).

```bash
vmware-nsx-security tag apply <vm-external-id> \
  --scope <scope> \
  --value <value> \
  [--dry-run] \
  [--target <name>]
```

| Option | Description |
|--------|-------------|
| `--scope` | Tag scope (e.g. `tier`, `env`, `owner`) |
| `--value` | Tag value (e.g. `web`, `production`) |

---

## `traceflow` — Packet Tracing

### `traceflow run`
Initiate a Traceflow and wait for results.

```bash
vmware-nsx-security traceflow run <src-lport-id> \
  --src-ip <ip> \
  --dst-ip <ip> \
  [--proto TCP|UDP|ICMP] \
  [--dst-port <port>] \
  [--target <name>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--src-ip` | required | Source IP for probe packet |
| `--dst-ip` | required | Destination IP |
| `--proto` | TCP | Protocol: TCP, UDP, or ICMP |
| `--dst-port` | 80 | Destination port (TCP/UDP) |

---

## `idps` — IDPS Operations

### `idps profiles`
List all IDPS profiles.

```bash
vmware-nsx-security idps profiles [--target <name>]
```

### `idps status`
Get IDPS engine status.

```bash
vmware-nsx-security idps status [--target <name>]
```

---

## `doctor` — Environment Diagnostics

Run pre-flight checks: config file, .env permissions, config parse, passwords, network reachability, NSX authentication, NSX version, MCP server import.

```bash
vmware-nsx-security doctor [--skip-auth] [--config <path>]
```

| Option | Description |
|--------|-------------|
| `--skip-auth` | Skip authentication tests (network check only) |
| `--config` | Override config file path |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VMWARE_NSX_SECURITY_CONFIG` | Path to config YAML file |
| `VMWARE_NSX_SECURITY_<TARGET>_PASSWORD` | Password for target (hyphens → underscores, uppercase) |

**Password examples**:
- Target `nsx-prod` → `VMWARE_NSX_SECURITY_NSX_PROD_PASSWORD`
- Target `nsx-lab` → `VMWARE_NSX_SECURITY_NSX_LAB_PASSWORD`
