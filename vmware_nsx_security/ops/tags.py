"""VM NSX Tag management operations.

NSX Tags are key-value metadata labels applied to virtual machines.
They are used by security groups (Groups with Condition expressions)
to dynamically include or exclude VMs from firewall policies.

APIs used:
  GET  /api/v1/fabric/virtual-machines?display_name=<name>
  POST /api/v1/fabric/tags/tag?action=add_tag
  POST /api/v1/fabric/tags/tag?action=remove_tag
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.tags")

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _sanitize(text: str, max_len: int = 500) -> str:
    """Strip control characters and truncate to max_len."""
    if not text:
        return text
    return _CONTROL_CHAR_RE.sub("", text[:max_len])


# ---------------------------------------------------------------------------
# VM tag list
# ---------------------------------------------------------------------------


def list_vm_tags(client: NsxClient, vm_display_name: str) -> dict:
    """List all NSX tags currently applied to a virtual machine.

    Looks up the VM by display name and returns all scope/value tag pairs.

    Args:
        client: Authenticated NsxClient instance.
        vm_display_name: Display name of the virtual machine to query.

    Returns:
        Dict with 'vm_id', 'display_name', and 'tags' list (each tag
        has 'scope' and 'tag' fields).

    Raises:
        KeyError: If no VM with that display name is found.
        ValueError: If multiple VMs share the same display name.
    """
    safe_name = _sanitize(vm_display_name)
    data = client.get(
        "/api/v1/fabric/virtual-machines",
        params={"display_name": safe_name},
    )
    vms = data.get("results", [])

    if not vms:
        raise KeyError(f"No virtual machine found with display_name='{safe_name}'")
    if len(vms) > 1:
        names = [v.get("display_name", "") for v in vms]
        raise ValueError(
            f"Multiple VMs found with display_name='{safe_name}': {names}. "
            "Use external_id to disambiguate."
        )

    vm = vms[0]
    return {
        "vm_id": _sanitize(vm.get("external_id", "")),
        "display_name": _sanitize(vm.get("display_name", "")),
        "power_state": vm.get("power_state", ""),
        "tags": vm.get("tags", []),
    }


# ---------------------------------------------------------------------------
# Apply / remove VM tag
# ---------------------------------------------------------------------------


def apply_vm_tag(
    client: NsxClient,
    vm_id: str,
    tag_scope: str,
    tag_value: str,
) -> dict:
    """Apply an NSX tag to a virtual machine.

    Uses POST /api/v1/fabric/tags/tag?action=add_tag. The tag is
    added non-destructively — existing tags on the VM are preserved.

    Args:
        client: Authenticated NsxClient instance.
        vm_id: VM external ID (fabric ID, not display name).
        tag_scope: Tag scope string (e.g. 'env', 'tier', 'owner').
        tag_value: Tag value string (e.g. 'production', 'web').

    Returns:
        Dict with 'status', 'vm_id', 'scope', and 'tag' keys.
    """
    body: dict[str, Any] = {
        "external_id": vm_id,
        "resource_type": "VirtualMachine",
        "tags": [
            {
                "scope": _sanitize(tag_scope),
                "tag": _sanitize(tag_value),
            }
        ],
    }
    client.post("/api/v1/fabric/tags/tag?action=add_tag", body)
    _log.info("Applied tag %s=%s to VM %s", tag_scope, tag_value, vm_id)
    return {
        "status": "applied",
        "vm_id": vm_id,
        "scope": tag_scope,
        "tag": tag_value,
    }


def remove_vm_tag(
    client: NsxClient,
    vm_id: str,
    tag_scope: str,
    tag_value: str,
) -> dict:
    """Remove an NSX tag from a virtual machine.

    Uses POST /api/v1/fabric/tags/tag?action=remove_tag.

    Args:
        client: Authenticated NsxClient instance.
        vm_id: VM external ID (fabric ID, not display name).
        tag_scope: Tag scope string to remove.
        tag_value: Tag value string to remove.

    Returns:
        Dict with 'status', 'vm_id', 'scope', and 'tag' keys.
    """
    body: dict[str, Any] = {
        "external_id": vm_id,
        "resource_type": "VirtualMachine",
        "tags": [
            {
                "scope": _sanitize(tag_scope),
                "tag": _sanitize(tag_value),
            }
        ],
    }
    client.post("/api/v1/fabric/tags/tag?action=remove_tag", body)
    _log.info("Removed tag %s=%s from VM %s", tag_scope, tag_value, vm_id)
    return {
        "status": "removed",
        "vm_id": vm_id,
        "scope": tag_scope,
        "tag": tag_value,
    }
