"""MCP server wrapping VMware NSX Security operations.

This module is the thin entrypoint: it imports ``mcp_server.tools`` (which
registers all 21 ``@mcp.tool()`` functions onto the shared ``mcp`` instance),
re-exports the tool functions and shared plumbing for direct import, and
exposes ``main()`` as the ``vmware-nsx-security-mcp`` console entry point.
The per-tool bodies now live in ``mcp_server/tools/*.py`` grouped by domain;
the shared connection/audit/error helpers live in ``mcp_server/_shared.py``.

Tool categories
---------------
* **Read-only** (no side effects): list_dfw_policies, get_dfw_policy,
  list_dfw_rules, list_groups, get_group, list_vm_tags,
  get_traceflow_result, list_idps_profiles, get_idps_status,
  get_dfw_rule_stats

* **Write** (mutate state): create_dfw_policy, update_dfw_policy,
  delete_dfw_policy, create_dfw_rule, update_dfw_rule, delete_dfw_rule,
  create_group, delete_group, apply_vm_tag, remove_vm_tag, run_traceflow
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

# Importing the tools package executes every @mcp.tool() decorator and
# registers all 21 tools onto the shared `mcp` instance.
import mcp_server.tools  # noqa: F401
from mcp_server._shared import (  # noqa: F401
    _DOCTOR_HINT,
    _audit,
    _get_connection,
    _safe_error,
    _write_error,
    logger,
    mcp,
)

# Re-export the tool functions so `from mcp_server.server import apply_vm_tag`
# and similar direct imports keep working after the domain split.
from mcp_server.tools.dfw_policy import (  # noqa: F401
    create_dfw_policy,
    delete_dfw_policy,
    get_dfw_policy,
    list_dfw_policies,
    update_dfw_policy,
)
from mcp_server.tools.dfw_rules import (  # noqa: F401
    create_dfw_rule,
    delete_dfw_rule,
    get_dfw_rule_stats,
    list_dfw_rules,
    update_dfw_rule,
)
from mcp_server.tools.groups import (  # noqa: F401
    create_group,
    delete_group,
    get_group,
    list_groups,
)
from mcp_server.tools.idps import (  # noqa: F401
    get_idps_status,
    list_idps_profiles,
)
from mcp_server.tools.tags import (  # noqa: F401
    apply_vm_tag,
    list_vm_tags,
    remove_vm_tag,
)
from mcp_server.tools.traceflow import (  # noqa: F401
    get_traceflow_result,
    run_traceflow,
)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server using stdio transport."""
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
