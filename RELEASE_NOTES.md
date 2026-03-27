# Release Notes

---

## v1.3.0 — 2026-03-27

### Initial release

- 20 MCP tools: 10 read-only + 10 write operations
- DFW: security policy CRUD (6 tools) + rule CRUD + rule stats (4 tools)
- Security groups: list, get, create, delete with dependency checks (4 tools)
- VM Tags: list VM tags, apply tag (2 tools)
- Traceflow: run trace with polling + get result (2 tools)
- IDPS: list profiles, get engine status (2 tools)
- Safety: `delete_dfw_policy` blocks if active rules exist; `delete_group` blocks if DFW-referenced
- SKILL.md with progressive disclosure (Anthropic best practices)
- CLI (`vmware-nsx-security`) with typer — policy/rule/group/tag/traceflow/idps subcommands
- MCP server (20 tools) via stdio transport
- Docker one-command launch
- `vmware-nsx-security doctor` — 8-check environment diagnostics
- Audit logging (JSON Lines) for all write operations
- `references/`: cli-reference.md, capabilities.md, setup-guide.md
- `examples/mcp-configs/`: 3 agent config templates (Claude Code, Cursor, Goose)
- README.md and README-CN.md with companion skills, workflows, troubleshooting

**PyPI**: `uv tool install vmware-nsx-security==1.3.0`
