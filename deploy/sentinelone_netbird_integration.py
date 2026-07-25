#!/usr/bin/env python3
"""
SentinelOne + NetBird integration helper.

Usage examples:
  1) Configure NetBird managed SentinelOne integration:
     python deploy/sentinelone_netbird_integration.py configure \
       --netbird-url https://netbird.example.com \
       --netbird-token "$NETBIRD_TOKEN" \
       --s1-api-url https://usea1-partners.sentinelone.net \
       --s1-api-token "$S1_API_TOKEN" \
       --group-id ch8i4ug6lnn4g9hqv7m0 \
       --last-synced-interval 24 \
       --require-firewall-enabled \
       --require-is-active

  2) Fallback audit mode (when EDR route is unavailable):
     python deploy/sentinelone_netbird_integration.py audit \
       --netbird-url https://netbird.example.com \
       --netbird-token "$NETBIRD_TOKEN" \
       --s1-api-url https://usea1-partners.sentinelone.net \
       --s1-api-token "$S1_API_TOKEN" \
       --report-json /tmp/s1_netbird_audit.json

  3) Enforce: block NetBird users whose machine security score < 90:
     python deploy/sentinelone_netbird_integration.py enforce \
       --netbird-url https://netbird.example.com \
       --netbird-token "$NETBIRD_TOKEN" \
       --s1-api-url https://usea1-partners.sentinelone.net \
       --s1-api-token "$S1_API_TOKEN" \
       --score-threshold 90 \
       --report-json /tmp/s1_enforce_report.json

Security Score (0-100) is computed from SentinelOne agent health indicators:
  - infected=false           +25 pts
  - activeThreats=0          +20 pts
  - firewallEnabled=true     +15 pts
  - isActive=true            +10 pts
  - isUpToDate=true          +10 pts
  - encryptedApplications    +10 pts
  - networkStatus=connected  +10 pts

Score >= threshold => PASS (user stays active)
Score <  threshold => FAIL (user gets blocked in NetBird)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib import error, parse, request


@dataclass
class APIError(Exception):
    status: int
    body: str
    url: str

    def __str__(self) -> str:
        return f"HTTP {self.status} for {self.url}: {self.body}"


def _normalize_base_url(url: str) -> str:
    return url.rstrip("/")


def _http_json(
    method: str,
    url: str,
    headers: Dict[str, str],
    payload: Optional[Dict[str, Any]] = None,
    timeout: int = 20,
) -> Tuple[int, Any]:
    data = None
    req_headers = dict(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    req = request.Request(url=url, method=method.upper(), headers=req_headers, data=data)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if not body:
                return resp.status, {}
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, {"raw": body}
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise APIError(status=exc.code, body=body, url=url) from exc
    except error.URLError as exc:
        raise RuntimeError(f"request failed for {url}: {exc}") from exc


def _build_match_attributes(args: argparse.Namespace) -> Dict[str, Any]:
    attrs: Dict[str, Any] = {"active_threats": args.max_active_threats}
    if not args.allow_infected:
        attrs["infected"] = False
    if args.require_firewall_enabled:
        attrs["firewall_enabled"] = True
    if args.require_is_active:
        attrs["is_active"] = True
    if args.require_up_to_date:
        attrs["is_up_to_date"] = True
    if args.network_status:
        attrs["network_status"] = args.network_status
    if args.operational_state:
        attrs["operational_state"] = args.operational_state
    return attrs


def _netbird_headers(token: str) -> Dict[str, str]:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }


def _sentinel_headers(token: str) -> Dict[str, str]:
    return {
        "Accept": "application/json",
        "Authorization": f"ApiToken {token}",
    }


def configure_integration(args: argparse.Namespace) -> int:
    base = _normalize_base_url(args.netbird_url)
    endpoint = f"{base}/api/integrations/edr/sentinelone"
    payload: Dict[str, Any] = {
        "api_token": args.s1_api_token,
        "api_url": _normalize_base_url(args.s1_api_url),
        "groups": args.group_id,
        "last_synced_interval": args.last_synced_interval,
        "enabled": (not args.disable),
        "match_attributes": _build_match_attributes(args),
    }

    headers = _netbird_headers(args.netbird_token)
    method = "POST"
    try:
        status, _ = _http_json("GET", endpoint, headers=headers, timeout=args.timeout)
        if status == 200:
            method = "PUT"
    except APIError as exc:
        if exc.status not in (404,):
            print(f"[ERROR] NetBird EDR check failed: {exc}", file=sys.stderr)
            return 2
        method = "POST"

    try:
        status, body = _http_json(method, endpoint, headers=headers, payload=payload, timeout=args.timeout)
    except APIError as exc:
        if exc.status == 404:
            print(
                "[WARN] This NetBird deployment does not expose /api/integrations/edr/sentinelone.\n"
                "       Use `audit` mode for a lightweight Python-only integration.",
                file=sys.stderr,
            )
            return 3
        print(f"[ERROR] Failed to {method} integration: {exc}", file=sys.stderr)
        return 2

    print(f"[OK] {method} /api/integrations/edr/sentinelone -> {status}")
    print(json.dumps(body, indent=2, ensure_ascii=True))
    return 0


def _extract_agents(page: Any) -> List[Dict[str, Any]]:
    if isinstance(page, dict):
        if isinstance(page.get("data"), list):
            return page["data"]
        if isinstance(page.get("agents"), list):
            return page["agents"]
    if isinstance(page, list):
        return page
    return []


def _extract_next_cursor(page: Any) -> Optional[str]:
    if not isinstance(page, dict):
        return None
    # SentinelOne commonly uses pagination.nextCursor or pagination.nextCursorToken
    pagination = page.get("pagination")
    if isinstance(pagination, dict):
        for key in ("nextCursor", "nextCursorToken", "cursor", "next"):
            value = pagination.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def fetch_sentinel_agents(args: argparse.Namespace) -> List[Dict[str, Any]]:
    base = _normalize_base_url(args.s1_api_url)
    endpoint = f"{base}/web/api/v2.1/agents"
    headers = _sentinel_headers(args.s1_api_token)
    all_agents: List[Dict[str, Any]] = []
    cursor: Optional[str] = None
    page_count = 0

    while True:
        page_count += 1
        query = {"limit": str(args.limit)}
        if cursor:
            query["cursor"] = cursor
        url = f"{endpoint}?{parse.urlencode(query)}"
        _, body = _http_json("GET", url, headers=headers, timeout=args.timeout)
        agents = _extract_agents(body)
        all_agents.extend(agents)

        if len(agents) < args.limit:
            break

        cursor = _extract_next_cursor(body)
        if not cursor or page_count >= args.max_pages:
            break

    return all_agents


def fetch_netbird_peers(args: argparse.Namespace) -> List[Dict[str, Any]]:
    base = _normalize_base_url(args.netbird_url)
    endpoint = f"{base}/api/peers"
    _, peers = _http_json("GET", endpoint, headers=_netbird_headers(args.netbird_token), timeout=args.timeout)
    if isinstance(peers, list):
        return peers
    return []


def _host_key(value: str) -> str:
    v = value.strip().lower()
    if "." in v:
        v = v.split(".", 1)[0]
    return v


def _agent_hostname(agent: Dict[str, Any]) -> str:
    for key in ("computerName", "name", "hostname", "host_name"):
        value = agent.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _agent_field(agent: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in agent:
            return agent[key]
    return None


SCORE_WEIGHTS: List[Tuple[str, int, Any]] = [
    # (description, max_points, ideal_value)
    # Total = 100
]


def compute_security_score(agent: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Compute a 0-100 security score from SentinelOne agent health indicators."""
    breakdown: Dict[str, Any] = {}
    score = 0

    infected = _agent_field(agent, "infected", "isInfected")
    pts = 25 if infected is False else 0
    breakdown["infected"] = {"value": infected, "points": pts, "max": 25}
    score += pts

    active_threats = _agent_field(agent, "activeThreats", "active_threats", "threatsCount")
    if not isinstance(active_threats, (int, float)):
        active_threats = None
    pts = 20 if (isinstance(active_threats, (int, float)) and active_threats == 0) else 0
    breakdown["active_threats"] = {"value": active_threats, "points": pts, "max": 20}
    score += pts

    firewall = _agent_field(agent, "firewallEnabled", "firewall_enabled")
    pts = 15 if firewall is True else 0
    breakdown["firewall_enabled"] = {"value": firewall, "points": pts, "max": 15}
    score += pts

    is_active = _agent_field(agent, "isActive", "is_active")
    pts = 10 if is_active is True else 0
    breakdown["is_active"] = {"value": is_active, "points": pts, "max": 10}
    score += pts

    is_up_to_date = _agent_field(agent, "isUpToDate", "is_up_to_date")
    pts = 10 if is_up_to_date is True else 0
    breakdown["is_up_to_date"] = {"value": is_up_to_date, "points": pts, "max": 10}
    score += pts

    encrypted = _agent_field(agent, "encryptedApplications", "encrypted_applications")
    pts = 10 if encrypted is True else 0
    breakdown["encrypted_applications"] = {"value": encrypted, "points": pts, "max": 10}
    score += pts

    net_status = _agent_field(agent, "networkStatus", "network_status")
    pts = 10 if (isinstance(net_status, str) and net_status.lower() == "connected") else 0
    breakdown["network_status"] = {"value": net_status, "points": pts, "max": 10}
    score += pts

    return score, breakdown


def fetch_netbird_users(args: argparse.Namespace) -> List[Dict[str, Any]]:
    base = _normalize_base_url(args.netbird_url)
    endpoint = f"{base}/api/users"
    _, users = _http_json("GET", endpoint, headers=_netbird_headers(args.netbird_token), timeout=args.timeout)
    if isinstance(users, list):
        return users
    return []


def block_netbird_user(args: argparse.Namespace, user: Dict[str, Any]) -> bool:
    base = _normalize_base_url(args.netbird_url)
    user_id = user["id"]
    endpoint = f"{base}/api/users/{user_id}"
    payload = {
        "role": user.get("role", "user"),
        "auto_groups": user.get("auto_groups", []),
        "is_blocked": True,
    }
    try:
        status, _ = _http_json("PUT", endpoint, headers=_netbird_headers(args.netbird_token),
                               payload=payload, timeout=args.timeout)
        return 200 <= status < 300
    except APIError as exc:
        print(f"  [ERROR] Failed to block user {user_id}: {exc}", file=sys.stderr)
        return False


def unblock_netbird_user(args: argparse.Namespace, user: Dict[str, Any]) -> bool:
    base = _normalize_base_url(args.netbird_url)
    user_id = user["id"]
    endpoint = f"{base}/api/users/{user_id}"
    payload = {
        "role": user.get("role", "user"),
        "auto_groups": user.get("auto_groups", []),
        "is_blocked": False,
    }
    try:
        status, _ = _http_json("PUT", endpoint, headers=_netbird_headers(args.netbird_token),
                               payload=payload, timeout=args.timeout)
        return 200 <= status < 300
    except APIError as exc:
        print(f"  [ERROR] Failed to unblock user {user_id}: {exc}", file=sys.stderr)
        return False


def enforce(args: argparse.Namespace) -> int:
    """Score every SentinelOne agent, match to NetBird peers/users, block those below threshold."""
    try:
        agents = fetch_sentinel_agents(args)
    except Exception as exc:
        print(f"[ERROR] Failed to fetch SentinelOne agents: {exc}", file=sys.stderr)
        return 2

    try:
        peers = fetch_netbird_peers(args)
    except Exception as exc:
        print(f"[ERROR] Failed to fetch NetBird peers: {exc}", file=sys.stderr)
        return 2

    try:
        users = fetch_netbird_users(args)
    except Exception as exc:
        print(f"[ERROR] Failed to fetch NetBird users: {exc}", file=sys.stderr)
        return 2

    peer_by_host: Dict[str, Dict[str, Any]] = {}
    for peer in peers:
        for key in ("hostname", "name"):
            value = peer.get(key)
            if isinstance(value, str) and value.strip():
                peer_by_host[_host_key(value)] = peer

    user_by_id: Dict[str, Dict[str, Any]] = {}
    for user in users:
        uid = user.get("id")
        if uid:
            user_by_id[uid] = user

    threshold = args.score_threshold
    report: List[Dict[str, Any]] = []
    blocked_count = 0
    unblocked_count = 0
    skipped_count = 0

    for agent in agents:
        hostname = _agent_hostname(agent)
        if not hostname:
            continue

        score, breakdown = compute_security_score(agent)
        passed = score >= threshold
        peer = peer_by_host.get(_host_key(hostname))
        peer_id = peer.get("id") if isinstance(peer, dict) else None
        user_id = peer.get("user_id") if isinstance(peer, dict) else None
        user = user_by_id.get(user_id) if user_id else None

        entry: Dict[str, Any] = {
            "hostname": hostname,
            "sentinel_agent_id": _agent_field(agent, "id", "agentId", "uuid"),
            "security_score": score,
            "threshold": threshold,
            "passed": passed,
            "breakdown": breakdown,
            "netbird_peer_id": peer_id,
            "netbird_user_id": user_id,
            "action": "none",
        }

        if not passed and user and not args.dry_run:
            if user.get("is_blocked"):
                entry["action"] = "already_blocked"
                skipped_count += 1
            else:
                ok = block_netbird_user(args, user)
                entry["action"] = "blocked" if ok else "block_failed"
                if ok:
                    blocked_count += 1
                    print(f"  [BLOCK] {hostname} score={score}<{threshold} -> blocked user {user_id}")
        elif not passed and user and args.dry_run:
            entry["action"] = "would_block"
            blocked_count += 1
            print(f"  [DRY-RUN] {hostname} score={score}<{threshold} -> would block user {user_id}")
        elif passed and user and args.auto_unblock and not args.dry_run:
            if user.get("is_blocked"):
                ok = unblock_netbird_user(args, user)
                entry["action"] = "unblocked" if ok else "unblock_failed"
                if ok:
                    unblocked_count += 1
                    print(f"  [UNBLOCK] {hostname} score={score}>={threshold} -> unblocked user {user_id}")
        elif passed and user and args.auto_unblock and args.dry_run:
            if user.get("is_blocked"):
                entry["action"] = "would_unblock"
                unblocked_count += 1
                print(f"  [DRY-RUN] {hostname} score={score}>={threshold} -> would unblock user {user_id}")
        elif not passed and not peer:
            entry["action"] = "no_matching_peer"

        report.append(entry)

    fail_count = sum(1 for r in report if not r["passed"])
    pass_count = sum(1 for r in report if r["passed"])

    print(f"\n{'='*60}")
    print(f"SentinelOne agents scanned : {len(agents)}")
    print(f"Security score threshold   : {threshold}")
    print(f"PASS (>= {threshold})              : {pass_count}")
    print(f"FAIL (<  {threshold})              : {fail_count}")
    if args.dry_run:
        print(f"Users WOULD be blocked     : {blocked_count}")
        print(f"Users WOULD be unblocked   : {unblocked_count}")
    else:
        print(f"Users blocked              : {blocked_count}")
        print(f"Users unblocked            : {unblocked_count}")
        print(f"Users already blocked      : {skipped_count}")
    print(f"{'='*60}")

    if report:
        print(f"\nFailed machines (score < {threshold}):")
        for item in sorted(report, key=lambda x: x["security_score"]):
            if not item["passed"]:
                print(
                    f"  - {item['hostname']}: score={item['security_score']} "
                    f"action={item['action']} user={item.get('netbird_user_id') or 'N/A'}"
                )

    if args.report_json:
        with open(args.report_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=True)
        print(f"\nFull report saved: {args.report_json}")

    return 1 if fail_count > 0 else 0


def _is_agent_compliant(agent: Dict[str, Any], args: argparse.Namespace) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    active_threats = _agent_field(agent, "activeThreats", "active_threats", "threatsCount")
    if isinstance(active_threats, (int, float)) and active_threats > args.max_active_threats:
        reasons.append(f"active_threats>{args.max_active_threats}")

    infected = _agent_field(agent, "infected", "isInfected")
    if not args.allow_infected and infected is True:
        reasons.append("infected=true")

    firewall_enabled = _agent_field(agent, "firewallEnabled", "firewall_enabled")
    if args.require_firewall_enabled and firewall_enabled is not True:
        reasons.append("firewall_enabled!=true")

    is_active = _agent_field(agent, "isActive", "is_active")
    if args.require_is_active and is_active is not True:
        reasons.append("is_active!=true")

    is_up_to_date = _agent_field(agent, "isUpToDate", "is_up_to_date")
    if args.require_up_to_date and is_up_to_date is not True:
        reasons.append("is_up_to_date!=true")

    network_status = _agent_field(agent, "networkStatus", "network_status")
    if args.network_status and isinstance(network_status, str):
        if network_status.lower() != args.network_status.lower():
            reasons.append(f"network_status!={args.network_status}")
    elif args.network_status and network_status is None:
        reasons.append(f"network_status_missing({args.network_status})")

    if args.operational_state:
        operational_state = _agent_field(agent, "operationalState", "operational_state")
        if not isinstance(operational_state, str) or operational_state.lower() != args.operational_state.lower():
            reasons.append(f"operational_state!={args.operational_state}")

    return len(reasons) == 0, reasons


def audit(args: argparse.Namespace) -> int:
    try:
        agents = fetch_sentinel_agents(args)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[ERROR] Failed to fetch SentinelOne agents: {exc}", file=sys.stderr)
        return 2

    try:
        peers = fetch_netbird_peers(args)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[ERROR] Failed to fetch NetBird peers: {exc}", file=sys.stderr)
        return 2

    peer_by_host: Dict[str, Dict[str, Any]] = {}
    for peer in peers:
        for key in ("hostname", "name"):
            value = peer.get(key)
            if isinstance(value, str) and value.strip():
                peer_by_host[_host_key(value)] = peer

    report: List[Dict[str, Any]] = []
    for agent in agents:
        hostname = _agent_hostname(agent)
        if not hostname:
            continue
        compliant, reasons = _is_agent_compliant(agent, args)
        if compliant:
            continue
        peer = peer_by_host.get(_host_key(hostname))
        report.append(
            {
                "hostname": hostname,
                "sentinel_agent_id": _agent_field(agent, "id", "agentId", "uuid"),
                "non_compliant_reasons": reasons,
                "netbird_peer_id": peer.get("id") if isinstance(peer, dict) else None,
                "netbird_peer_ip": peer.get("ip") if isinstance(peer, dict) else None,
            }
        )

    print(f"SentinelOne agents checked: {len(agents)}")
    print(f"NetBird peers checked: {len(peers)}")
    print(f"Non-compliant agents matched in NetBird: {len([r for r in report if r['netbird_peer_id']])}")
    print(f"Non-compliant agents unmatched in NetBird: {len([r for r in report if not r['netbird_peer_id']])}")

    if report:
        print("\nTop findings:")
        for item in report[:20]:
            print(
                f"- {item['hostname']}: {','.join(item['non_compliant_reasons'])} "
                f"(peer_id={item['netbird_peer_id'] or 'N/A'})"
            )

    if args.report_json:
        with open(args.report_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=True)
        print(f"\nReport saved: {args.report_json}")

    return 1 if report else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelOne + NetBird integration helper")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--netbird-url", required=True, help="NetBird base URL, e.g. https://netbird.example.com")
    common.add_argument("--netbird-token", required=True, help="NetBird admin API token")
    common.add_argument("--s1-api-url", required=True, help="SentinelOne API base URL")
    common.add_argument("--s1-api-token", required=True, help="SentinelOne API token")
    common.add_argument("--max-active-threats", type=int, default=0, help="Max allowed active threats")
    common.add_argument("--allow-infected", action="store_true", help="Allow infected hosts")
    common.add_argument("--require-firewall-enabled", action="store_true", help="Require firewall enabled")
    common.add_argument("--require-is-active", action="store_true", help="Require active status")
    common.add_argument("--require-up-to-date", action="store_true", help="Require up-to-date status")
    common.add_argument(
        "--network-status",
        choices=("connected", "disconnected", "quarantined"),
        help="Required network status",
    )
    common.add_argument("--operational-state", help="Required operational state value")

    sub = parser.add_subparsers(dest="command", required=True)

    p_config = sub.add_parser("configure", parents=[common], help="Create/Update NetBird SentinelOne integration")
    p_config.add_argument(
        "--group-id",
        action="append",
        required=True,
        help="NetBird group ID for integration scope (repeatable)",
    )
    p_config.add_argument(
        "--last-synced-interval",
        type=int,
        default=24,
        help="Required sync interval in hours (minimum 24)",
    )
    p_config.add_argument("--disable", action="store_true", help="Disable integration after creation/update")

    p_audit = sub.add_parser("audit", parents=[common], help="Fallback Python-only compliance audit")
    p_audit.add_argument("--limit", type=int, default=200, help="SentinelOne page size")
    p_audit.add_argument("--max-pages", type=int, default=50, help="Safety cap for API pages")
    p_audit.add_argument("--report-json", help="Write findings to JSON file")

    p_enforce = sub.add_parser(
        "enforce", parents=[common],
        help="Score agents and block/unblock NetBird users based on security score threshold",
    )
    p_enforce.add_argument("--limit", type=int, default=200, help="SentinelOne page size")
    p_enforce.add_argument("--max-pages", type=int, default=50, help="Safety cap for API pages")
    p_enforce.add_argument(
        "--score-threshold", type=int, default=90,
        help="Minimum security score (0-100) to stay active. Default: 90",
    )
    p_enforce.add_argument(
        "--dry-run", action="store_true",
        help="Only report; do not actually block/unblock users",
    )
    p_enforce.add_argument(
        "--auto-unblock", action="store_true",
        help="Automatically unblock users whose score rises back above threshold",
    )
    p_enforce.add_argument("--report-json", help="Write detailed report to JSON file")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "configure":
        if args.last_synced_interval < 24:
            print("[ERROR] --last-synced-interval must be >= 24", file=sys.stderr)
            return 2
        return configure_integration(args)

    if args.command == "audit":
        return audit(args)

    if args.command == "enforce":
        if not 0 <= args.score_threshold <= 100:
            print("[ERROR] --score-threshold must be 0-100", file=sys.stderr)
            return 2
        return enforce(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
