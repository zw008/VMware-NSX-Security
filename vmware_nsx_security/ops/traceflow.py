"""Traceflow operations — packet path tracing through NSX overlay.

Traceflow injects a synthetic probe packet into the NSX data plane and
returns hop-by-hop observations including forwarding decisions and
firewall rule hits.

APIs used:
  POST /api/v1/traceflows           — initiate a traceflow request
  GET  /api/v1/traceflows/<id>      — poll for completion
  GET  /api/v1/traceflows/<id>/observations — fetch observations/hop data
  DELETE /api/v1/traceflows/<id>    — clean up after retrieval
"""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.traceflow")

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

_POLL_INTERVAL = 2  # seconds between status checks
_MAX_POLLS = 15     # up to 30 seconds total wait time


def _sanitize(text: str, max_len: int = 500) -> str:
    """Strip control characters and truncate to max_len."""
    if not text:
        return text
    return _CONTROL_CHAR_RE.sub("", text[:max_len])


# ---------------------------------------------------------------------------
# Traceflow
# ---------------------------------------------------------------------------


def run_traceflow(
    client: NsxClient,
    src_lport_id: str,
    src_ip: str,
    dst_ip: str,
    protocol: str = "TCP",
    dst_port: int = 80,
    src_port: int = 1234,
    ttl: int = 64,
    timeout_seconds: int = 20,
) -> dict:
    """Initiate a Traceflow and poll until it completes.

    Injects a probe packet from the source logical port and traces
    its path through the NSX overlay. Returns hop-by-hop observations
    including DFW rule hits.

    Args:
        client: Authenticated NsxClient instance.
        src_lport_id: Source logical port ID (attachment UUID of the VM NIC).
        src_ip: Source IP address of the probe packet.
        dst_ip: Destination IP address.
        protocol: IP protocol — TCP, UDP, or ICMP (default: TCP).
        dst_port: Destination port for TCP/UDP (default: 80).
        src_port: Source port for TCP/UDP (default: 1234).
        ttl: IP TTL value for the probe packet (default: 64).
        timeout_seconds: Maximum seconds to wait for completion (default: 20).

    Returns:
        Dict with traceflow_id, status, component observations list,
        and a summary of any DFW hits found along the path.
    """
    protocol = protocol.upper()
    if protocol not in ("TCP", "UDP", "ICMP"):
        raise ValueError(f"Invalid protocol '{protocol}'. Must be TCP, UDP, or ICMP.")

    # Build packet spec
    packet: dict[str, Any] = {
        "resource_type": "FieldsPacketData",
        "src_ip": _sanitize(src_ip),
        "dst_ip": _sanitize(dst_ip),
        "ip_ttl": ttl,
    }

    if protocol == "TCP":
        packet["transport_type"] = "TCP"
        packet["src_port"] = src_port
        packet["dst_port"] = dst_port
        packet["tcp_flags"] = 2  # SYN
    elif protocol == "UDP":
        packet["transport_type"] = "UDP"
        packet["src_port"] = src_port
        packet["dst_port"] = dst_port
    else:  # ICMP
        packet["transport_type"] = "ICMP"
        packet["icmp_type"] = 8
        packet["icmp_code"] = 0

    body: dict[str, Any] = {
        "lport_id": _sanitize(src_lport_id),
        "packet": packet,
    }

    # Initiate
    response = client.post("/api/v1/traceflows", body)
    tf_id = response.get("id", "")
    if not tf_id:
        return {"status": "error", "message": "Traceflow initiation returned no ID."}

    _log.info("Traceflow %s initiated: %s -> %s", tf_id, src_ip, dst_ip)

    # Poll for completion
    polls = min(_MAX_POLLS, timeout_seconds // _POLL_INTERVAL)
    status = "PENDING"
    for _ in range(polls):
        time.sleep(_POLL_INTERVAL)
        tf_data = client.get(f"/api/v1/traceflows/{tf_id}")
        status = tf_data.get("status", "PENDING")
        if status in ("COMPLETED", "FAILED", "PARTIAL"):
            break

    # Fetch observations
    observations: list[dict] = []
    dfw_hits: list[dict] = []
    try:
        obs_data = client.get(f"/api/v1/traceflows/{tf_id}/observations")
        raw_obs = obs_data.get("results", [])
        for obs in raw_obs:
            component = _sanitize(obs.get("component_name", ""))
            obs_type = _sanitize(obs.get("observation_type", ""))
            entry = {
                "component": component,
                "type": obs_type,
                "component_type": _sanitize(obs.get("component_type", "")),
                "transport_node": _sanitize(obs.get("transport_node_name", "")),
            }
            if obs_type == "DROPPED":
                entry["reason"] = _sanitize(obs.get("reason", ""))
                entry["acl_rule_id"] = _sanitize(str(obs.get("acl_rule_id", "")))
            observations.append(entry)

            # Collect DFW rule hits
            if obs.get("acl_rule_id"):
                dfw_hits.append({
                    "component": component,
                    "acl_rule_id": _sanitize(str(obs.get("acl_rule_id", ""))),
                    "action": _sanitize(obs.get("reason", "")),
                })
    except Exception as exc:
        _log.warning("Failed to fetch traceflow observations for %s: %s", tf_id, exc)

    # Clean up
    try:
        client.delete(f"/api/v1/traceflows/{tf_id}")
    except Exception:
        pass

    return {
        "traceflow_id": tf_id,
        "status": status,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "observation_count": len(observations),
        "observations": observations,
        "dfw_hits": dfw_hits,
    }


def get_traceflow_result(client: NsxClient, traceflow_id: str) -> dict:
    """Retrieve the current status and observations of an existing Traceflow.

    Use this if you initiated a traceflow and want to check its result
    later without waiting.

    Args:
        client: Authenticated NsxClient instance.
        traceflow_id: Traceflow ID returned by run_traceflow or a prior call.

    Returns:
        Dict with traceflow_id, status, and observations list.
    """
    if not re.match(r"^[\w\-]+$", traceflow_id):
        raise ValueError(f"Invalid traceflow_id: '{traceflow_id}'")

    tf_data = client.get(f"/api/v1/traceflows/{traceflow_id}")
    status = tf_data.get("status", "UNKNOWN")

    observations: list[dict] = []
    try:
        obs_data = client.get(f"/api/v1/traceflows/{traceflow_id}/observations")
        for obs in obs_data.get("results", []):
            observations.append({
                "component": _sanitize(obs.get("component_name", "")),
                "type": _sanitize(obs.get("observation_type", "")),
                "component_type": _sanitize(obs.get("component_type", "")),
                "transport_node": _sanitize(obs.get("transport_node_name", "")),
                "reason": _sanitize(obs.get("reason", "")),
            })
    except Exception as exc:
        _log.warning("Could not fetch observations: %s", exc)

    return {
        "traceflow_id": traceflow_id,
        "status": status,
        "observation_count": len(observations),
        "observations": observations,
    }
