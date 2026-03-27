# VMware NSX Security — Setup Guide

## Prerequisites

- NSX Manager 3.x or 4.x (NSX-T)
- An NSX admin account with DFW read/write permissions
- Python 3.10+ and `uv` installed

## 1. Install

```bash
uv tool install vmware-nsx-security
```

Verify:
```bash
vmware-nsx-security --help
```

## 2. Create Config Directory

```bash
mkdir -p ~/.vmware-nsx-security
```

## 3. Create Config File

Copy the example and edit:

```bash
# From the package source directory
cp config.example.yaml ~/.vmware-nsx-security/config.yaml
```

Or create manually:

```yaml
# ~/.vmware-nsx-security/config.yaml
targets:
  nsx-prod:
    host: nsx-manager.example.com
    username: admin
    port: 443
    verify_ssl: true
  nsx-lab:
    host: 10.0.0.50
    username: admin
    port: 443
    verify_ssl: false   # Allow self-signed cert in lab

default_target: nsx-prod
```

## 4. Set Passwords

Passwords are **never** stored in `config.yaml`. Use environment variables or a `.env` file:

```bash
# Create .env file
cat > ~/.vmware-nsx-security/.env << 'EOF'
VMWARE_NSX_SECURITY_NSX_PROD_PASSWORD=your_prod_password
VMWARE_NSX_SECURITY_NSX_LAB_PASSWORD=your_lab_password
EOF

# Secure the file — IMPORTANT
chmod 600 ~/.vmware-nsx-security/.env
```

**Password variable naming convention**: `VMWARE_NSX_SECURITY_<TARGET>_PASSWORD`
where `<TARGET>` is the target name uppercased with hyphens → underscores.

## 5. Verify Setup

```bash
vmware-nsx-security doctor
```

All checks should show PASS:
- Config file
- .env permissions (owner-only 600)
- Config parse (N targets configured)
- Password (set for each target)
- Network (TCP reachable on port 443)
- NSX auth (session created)
- NSX version (vX.Y.Z)
- MCP server import

## 6. Configure MCP Server

### Claude Code

Add to `~/.claude.json` (or `.claude.json` in your project):

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

### Cursor

In Cursor Settings → MCP Servers:

```json
{
  "vmware-nsx-security": {
    "command": "vmware-nsx-security-mcp",
    "env": {
      "VMWARE_NSX_SECURITY_CONFIG": "${HOME}/.vmware-nsx-security/config.yaml"
    }
  }
}
```

### Goose

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

## 7. Docker (Optional)

Build and run as a container:

```bash
docker-compose up --build
```

Mount your config:
```yaml
# docker-compose.yml already mounts ~/.vmware-nsx-security:/root/.vmware-nsx-security:ro
```

## Companion Skill Setup

For full NSX coverage, also install:

```bash
# NSX networking: segments, gateways, NAT, routing
uv tool install vmware-nsx-mgmt

# vSphere monitoring
uv tool install vmware-monitor
```

Configure each with its own config directory:
- NSX networking: `~/.vmware-nsx/config.yaml`
- NSX security: `~/.vmware-nsx-security/config.yaml`
- Monitor: `~/.vmware-monitor/config.yaml`

Both `vmware-nsx` and `vmware-nsx-security` can point to the same NSX Manager hosts — the config files are separate because the password env vars differ.

## Security Notes

- `config.yaml` should be readable only by your user: `chmod 600 ~/.vmware-nsx-security/config.yaml`
- `.env` must be `chmod 600` — the doctor check warns if it is too permissive
- Use a dedicated read/write NSX account for security operations, not the global `admin` superuser
- Audit logs are written to `~/.vmware-nsx-security/audit.log` (JSON Lines, append-only)
- The MCP server uses stdio transport — it never opens a network port; it is started on-demand by your AI agent
