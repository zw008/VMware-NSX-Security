# VMware NSX Security — Capabilities Reference

## DFW Policy Categories

NSX DFW policies are evaluated in category order (lower category = higher priority):

| Category | Priority | Typical Use |
|----------|:--------:|-------------|
| Emergency | 1 | Incident response — block specific IPs or VMs immediately |
| Infrastructure | 2 | DNS, NTP, vCenter management traffic |
| Environment | 3 | Cross-environment rules (e.g. prod → lab) |
| Application | 4 | Application-tier microsegmentation (most common) |

## DFW Rule Actions

| Action | Behaviour |
|--------|-----------|
| ALLOW | Permit the traffic |
| DROP | Silently discard the packet (no RST/ICMP) |
| REJECT | Discard + send TCP RST or ICMP unreachable |
| JUMP_TO_APPLICATION | Skip to Application category rules |

## Security Group Expression Types

Groups support three membership condition types (ANDed together):

| Type | Parameter | Example |
|------|-----------|---------|
| Tag Condition | `tag_scope` + `tag_value` | scope=tier, value=web |
| IP Address | `ip_addresses` | ['10.0.1.0/24', '10.0.2.5'] |
| Segment Path | `segment_paths` | ['/infra/segments/web-seg'] |

Multiple criteria in one group are ANDed (VM must match ALL conditions).

## Traceflow Packet Types

| Protocol | Fields | Notes |
|----------|--------|-------|
| TCP | src_ip, dst_ip, src_port, dst_port, TTL | SYN flag set automatically |
| UDP | src_ip, dst_ip, src_port, dst_port, TTL | |
| ICMP | src_ip, dst_ip, TTL | Echo request (type 8) |

## Traceflow Observation Types

| Type | Meaning |
|------|---------|
| FORWARDED | Packet forwarded to next hop |
| DROPPED | Packet dropped at this component (see `reason` + `acl_rule_id`) |
| DELIVERED | Packet delivered to destination |
| RECEIVED | Packet received at destination VM |

## IDPS Severity Levels

NSX IDPS signatures are classified by severity:

| Level | Score Range | Description |
|-------|-------------|-------------|
| CRITICAL | 9.0–10.0 | Immediate exploitation, remote code execution |
| HIGH | 7.0–8.9 | Significant risk, exploitable vulnerabilities |
| MEDIUM | 4.0–6.9 | Moderate risk, requires specific conditions |
| LOW | 0.1–3.9 | Informational, denial-of-service potential |

## NSX Tag Conventions

Best practice for NSX tag design:

| Scope | Example Values | Used For |
|-------|---------------|----------|
| `tier` | web, app, db | Application tier microsegmentation |
| `env` | prod, staging, dev | Environment separation |
| `owner` | team-a, finance | Policy ownership |
| `compliance` | pci, hipaa | Regulatory scope |

## API Endpoints Reference

| Operation | Method | Path |
|-----------|--------|------|
| List policies | GET | /policy/api/v1/infra/domains/default/security-policies |
| Get policy | GET | /policy/api/v1/infra/domains/default/security-policies/{id} |
| Create/replace policy | PUT | /policy/api/v1/infra/domains/default/security-policies/{id} |
| Update policy | PATCH | /policy/api/v1/infra/domains/default/security-policies/{id} |
| Delete policy | DELETE | /policy/api/v1/infra/domains/default/security-policies/{id} |
| List rules | GET | /policy/api/v1/infra/domains/default/security-policies/{id}/rules |
| Create/replace rule | PUT | .../rules/{rule-id} |
| Update rule | PATCH | .../rules/{rule-id} |
| Delete rule | DELETE | .../rules/{rule-id} |
| Rule statistics | GET | .../rules/{rule-id}/statistics |
| List groups | GET | /policy/api/v1/infra/domains/default/groups |
| Get group | GET | /policy/api/v1/infra/domains/default/groups/{id} |
| Create/replace group | PUT | /policy/api/v1/infra/domains/default/groups/{id} |
| Delete group | DELETE | /policy/api/v1/infra/domains/default/groups/{id} |
| Group members (VMs) | GET | /policy/api/v1/infra/domains/default/groups/{id}/members/virtual-machines |
| List VM tags | GET | /api/v1/fabric/virtual-machines?display_name={name} |
| Apply tag | POST | /api/v1/fabric/tags/tag?action=add_tag |
| Remove tag | POST | /api/v1/fabric/tags/tag?action=remove_tag |
| Create traceflow | POST | /api/v1/traceflows |
| Get traceflow | GET | /api/v1/traceflows/{id} |
| Traceflow observations | GET | /api/v1/traceflows/{id}/observations |
| Delete traceflow | DELETE | /api/v1/traceflows/{id} |
| IDPS profiles | GET | /policy/api/v1/infra/settings/firewall/security/intrusion-services/profiles |
| IDPS status | GET | /policy/api/v1/infra/settings/firewall/security/intrusion-services/status |
