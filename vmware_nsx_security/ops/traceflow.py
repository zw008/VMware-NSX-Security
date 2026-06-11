"""Traceflow operations — packet path tracing through NSX overlay.

Traceflow injects a synthetic probe packet into the NSX data plane and
returns hop-by-hop observations including forwarding decisions and
firewall rule hits.

APIs used:
  POST /api/v1/traceflows           — initiate a traceflow request
  GET  /api/v1/traceflows/<id>      — poll for completion
  GET  /api/v1/traceflows/<id>/observations — fetch observations/hop data
  DELETE /api/v1/traceflows/<id>    — clean up after retrieval

Note: these Manager (MP) API endpoints are deprecated in NSX 3.x/4.x but
remain functional. The Policy API successor lives under
/policy/api/v1/infra/traceflows.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from vmware_policy import sanitize

from vmware_nsx_security.ops._validate import validate_id as _validate_id

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.traceflow")

_POLL_INTERVAL = 2   # seconds between status checks
_MAX_POLLS = 150     # safety cap: up to 300 seconds total wait time

# IP protocol numbers for the FieldsPacketData ip_header
_IP_PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17, "ICMP": 1}


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
        Dict with traceflow_id, operation_state (IN_PROGRESS/FINISHED/
        FAILED), cleaned_up flag, component observations list, and a
        summary of any DFW hits found along the path.

        ``cleaned_up`` is True when the server-side traceflow object was
        deleted after retrieval. A traceflow still IN_PROGRESS at timeout
        is left in place (cleaned_up=False) so get_traceflow_result can
        poll it later — calling get_traceflow_result on a cleaned-up ID
        returns a 404.
    """
    protocol = protocol.upper()
    if protocol not in ("TCP", "UDP", "ICMP"):
        raise ValueError(f"Invalid protocol '{protocol}'. Must be TCP, UDP, or ICMP.")

    # Build packet spec. FieldsPacketData nests ip_header / transport_header;
    # transport_type is the L2 delivery mode (UNICAST), NOT the protocol.
    if protocol == "TCP":
        transport_header: dict[str, Any] = {
            "tcp_header": {"src_port": src_port, "dst_port": dst_port, "tcp_flags": 2}  # SYN
        }
    elif protocol == "UDP":
        transport_header = {
            "udp_header": {"src_port": src_port, "dst_port": dst_port}
        }
    else:  # ICMP
        transport_header = {"icmp_echo_request_header": {}}

    packet: dict[str, Any] = {
        "resource_type": "FieldsPacketData",
        "routed": True,
        "transport_type": "UNICAST",
        "ip_header": {
            "src_ip": sanitize(src_ip),
            "dst_ip": sanitize(dst_ip),
            "ttl": ttl,
            "protocol": _IP_PROTOCOL_NUMBERS[protocol],
        },
        "transport_header": transport_header,
    }

    body: dict[str, Any] = {
        "lport_id": sanitize(src_lport_id),
        "packet": packet,
    }

    # Initiate
    response = client.post("/api/v1/traceflows", body)
    tf_id = response.get("id", "")
    if not tf_id:
        return {"status": "error", "message": "Traceflow initiation returned no ID."}

    _log.info("Traceflow %s initiated: %s -> %s", tf_id, src_ip, dst_ip)

    # Poll for completion — the API reports `operation_state` with enum
    # IN_PROGRESS / FINISHED / FAILED. Honor the requested timeout up to the
    # _MAX_POLLS safety cap, and always poll at least once (the old
    # `timeout // interval` formula silently capped waits at 30s and produced
    # ZERO polls for timeout_seconds < 2).
    polls = max(1, min(_MAX_POLLS, timeout_seconds // _POLL_INTERVAL))
    operation_state = "IN_PROGRESS"
    for _ in range(polls):
        time.sleep(_POLL_INTERVAL)
        tf_data = client.get(f"/api/v1/traceflows/{tf_id}")
        operation_state = tf_data.get("operation_state", "IN_PROGRESS")
        if operation_state in ("FINISHED", "FAILED"):
            break

    # Fetch observations — discriminated by `resource_type`
    # (TraceflowObservationDelivered / Dropped / DroppedLogical /
    # Forwarded / Received / ...).
    observations: list[dict] = []
    dfw_hits: list[dict] = []
    try:
        obs_data = client.get(f"/api/v1/traceflows/{tf_id}/observations")
        raw_obs = obs_data.get("results", [])
        for obs in raw_obs:
            component = sanitize(obs.get("component_name", ""))
            rtype = sanitize(obs.get("resource_type", ""))
            entry = {
                "component": component,
                "resource_type": rtype,
                "component_type": sanitize(obs.get("component_type", "")),
                "transport_node": sanitize(obs.get("transport_node_name", "")),
            }
            # reason / acl_rule_id only exist on Dropped* observations
            if rtype.startswith("TraceflowObservationDropped"):
                entry["reason"] = sanitize(str(obs.get("reason", "")))
                entry["acl_rule_id"] = sanitize(str(obs.get("acl_rule_id", "")))
            observations.append(entry)

            # Collect DFW rule hits
            if obs.get("acl_rule_id"):
                dfw_hits.append({
                    "component": component,
                    "acl_rule_id": sanitize(str(obs.get("acl_rule_id", ""))),
                    "action": sanitize(str(obs.get("reason", ""))),
                })
    except Exception as exc:
        _log.warning("Failed to fetch traceflow observations for %s: %s", tf_id, exc)

    # Clean up — best-effort; a failed delete leaves a transient traceflow
    # that NSX ages out on its own, but log it so resource leaks are visible.
    # An IN_PROGRESS traceflow is NOT deleted: the caller may still poll it
    # via get_traceflow_result, and deleting it would 404 that lookup.
    cleaned_up = False
    if operation_state in ("FINISHED", "FAILED"):
        try:
            client.delete(f"/api/v1/traceflows/{tf_id}")
            cleaned_up = True
        except Exception as exc:
            _log.debug("Failed to clean up traceflow %s: %s", tf_id, exc)

    return {
        "traceflow_id": tf_id,
        "operation_state": operation_state,
        "cleaned_up": cleaned_up,
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
    later without waiting. Note: run_traceflow deletes FINISHED/FAILED
    traceflows after retrieval (see its cleaned_up field) — looking up a
    cleaned-up ID returns a 404; only IN_PROGRESS traceflows remain
    pollable here.

    Args:
        client: Authenticated NsxClient instance.
        traceflow_id: Traceflow ID returned by run_traceflow or a prior call.

    Returns:
        Dict with traceflow_id, operation_state (IN_PROGRESS/FINISHED/
        FAILED), and observations list (discriminated by resource_type).
    """
    _validate_id(traceflow_id, "traceflow_id")

    tf_data = client.get(f"/api/v1/traceflows/{traceflow_id}")
    operation_state = tf_data.get("operation_state", "UNKNOWN")

    observations: list[dict] = []
    try:
        obs_data = client.get(f"/api/v1/traceflows/{traceflow_id}/observations")
        for obs in obs_data.get("results", []):
            rtype = sanitize(obs.get("resource_type", ""))
            entry = {
                "component": sanitize(obs.get("component_name", "")),
                "resource_type": rtype,
                "component_type": sanitize(obs.get("component_type", "")),
                "transport_node": sanitize(obs.get("transport_node_name", "")),
            }
            # reason / acl_rule_id only exist on Dropped* observations
            if rtype.startswith("TraceflowObservationDropped"):
                entry["reason"] = sanitize(str(obs.get("reason", "")))
                entry["acl_rule_id"] = sanitize(str(obs.get("acl_rule_id", "")))
            observations.append(entry)
    except Exception as exc:
        _log.warning("Could not fetch observations: %s", exc)

    return {
        "traceflow_id": traceflow_id,
        "operation_state": operation_state,
        "observation_count": len(observations),
        "observations": observations,
    }
