from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any, Iterable

from .console import require_proven_local_console
from .util import AuditLog, UmzugError, rename_noreplace_at, require_root, run, which


IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
OFFLINE_GUARD_TABLE = "umzug_offline_guard"
MULLVAD_TABLE = "mullvad"
RECOVERY_SEARCH_PATH = "/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin"
OWNED_NFT_TABLES = (
    "umzug_vpn_bootstrap_guard",
    "umzug_vpn_lock",
    "umzug_host",
    OFFLINE_GUARD_TABLE,
)
OWNED_SYSTEMD_UNITS = (
    "umzug-firewall.service",
    "umzug-radio-off.service",
    "umzug-offline-guard.service",
)
OWNED_OPENRC_HOOKS = (
    Path("/etc/local.d/umzug-firewall.start"),
    Path("/etc/local.d/umzug-radio-off.start"),
    Path("/etc/local.d/umzug-offline-guard.start"),
)


def validate_interfaces(names: Iterable[str]) -> list[str]:
    result = sorted(set(names))
    if not result:
        raise UmzugError("at least one physical Ethernet interface is required")
    if any(not IFACE_RE.fullmatch(name) for name in result):
        raise UmzugError("invalid network interface name")
    return result


def _parse_resolver_token(token: str) -> tuple[str, str | None]:
    """parse a literal resolver address without performing name resolution."""

    value = token.strip().rstrip(",")
    if not value or len(value) > 256 or any(ord(char) < 0x20 for char in value):
        raise UmzugError("effective DNS configuration contains an invalid resolver")
    # resolvectl may annotate an address with a DNS-over-TLS server name.  the
    # annotation is not part of the route lookup, but retaining a strict
    # literal-IP requirement prevents this parser from resolving names itself.
    value = value.split("#", 1)[0]
    scope: str | None = None
    address_text = value
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]{1,5}))?", value)
        if match is None:
            raise UmzugError("effective DNS configuration contains an invalid resolver")
        address_text = match.group(1)
        if match.group(2) is not None and not 1 <= int(match.group(2)) <= 65535:
            raise UmzugError("effective DNS configuration contains an invalid resolver")
    else:
        try:
            ipaddress.ip_address(value.split("%", 1)[0])
        except ValueError:
            host, separator, port = value.rpartition(":")
            if not separator or not port.isdecimal():
                raise UmzugError("effective DNS configuration contains a non-literal resolver")
            try:
                parsed_host = ipaddress.ip_address(host)
            except ValueError as exc:
                raise UmzugError("effective DNS configuration contains a non-literal resolver") from exc
            if parsed_host.version != 4 or not 1 <= int(port) <= 65535:
                raise UmzugError("effective DNS configuration contains an invalid resolver")
            address_text = host
    if "%" in address_text:
        address_text, scope = address_text.rsplit("%", 1)
        if not IFACE_RE.fullmatch(scope):
            raise UmzugError("effective DNS resolver has an invalid interface scope")
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError as exc:
        raise UmzugError("effective DNS configuration contains a non-literal resolver") from exc
    return address.compressed, scope


def parse_effective_dns_sources(
    resolvectl_status: str | None,
    resolv_conf: str,
) -> list[dict[str, str | None]]:
    """extract literal resolver candidates and their link association.

    this is deliberately narrower than a full systemd-resolved parser.  Any
    value advertised in a DNS field must be a literal address; unsupported or
    ambiguous values fail closed instead of being silently ignored.
    """

    if resolvectl_status is not None and not isinstance(resolvectl_status, str):
        raise UmzugError("effective resolvectl DNS configuration is malformed")
    if not isinstance(resolv_conf, str):
        raise UmzugError("effective DNS configuration is unavailable")
    sources: list[dict[str, str | None]] = []

    def add(token: str, *, interface: str | None, origin: str) -> None:
        address, scope = _parse_resolver_token(token)
        if interface is not None and not IFACE_RE.fullmatch(interface):
            raise UmzugError("resolvectl exposed an invalid DNS link name")
        if scope is not None and interface is not None and scope != interface:
            raise UmzugError("effective DNS resolver has conflicting interface scopes")
        sources.append(
            {
                "address": address,
                "scope": scope,
                "interface": interface,
                "origin": origin,
            }
        )

    current_interface: str | None = None
    continuation: tuple[str, str | None, str] | None = None
    dns_field = re.compile(r"^\s*(Current DNS Server|DNS Servers|Fallback DNS Servers):\s*(.*?)\s*$")
    for raw_line in (resolvectl_status or "").splitlines():
        stripped = raw_line.strip()
        link = re.fullmatch(r"Link\s+[0-9]+\s+\(([^)]+)\)", stripped)
        if link is not None:
            current_interface = link.group(1)
            if not IFACE_RE.fullmatch(current_interface):
                raise UmzugError("resolvectl exposed an invalid DNS link name")
            continuation = None
            continue
        if stripped == "Global":
            current_interface = None
            continuation = None
            continue
        field = dns_field.match(raw_line)
        if field is not None:
            label, values = field.groups()
            origin = {
                "Current DNS Server": "resolvectl-current",
                "DNS Servers": "resolvectl-servers",
                "Fallback DNS Servers": "resolvectl-fallback",
            }[label]
            tokens = values.split()
            if not tokens:
                raise UmzugError("resolvectl exposed an empty DNS resolver field")
            for token in tokens:
                add(token, interface=current_interface, origin=origin)
            continuation = (label, current_interface, origin)
            continue
        if continuation is not None and raw_line[:1].isspace() and stripped:
            tokens = stripped.split()
            try:
                parsed = [_parse_resolver_token(token) for token in tokens]
            except UmzugError:
                if re.match(r"^[A-Z][A-Za-z0-9 ._-]{2,48}:", stripped):
                    continuation = None
                else:
                    raise UmzugError("resolvectl exposed an unparseable DNS resolver continuation")
            else:
                _label, interface, origin = continuation
                for token, _parsed in zip(tokens, parsed, strict=True):
                    add(token, interface=interface, origin=origin)
                continue
        continuation = None

    for raw_line in resolv_conf.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if fields[0] != "nameserver":
            continue
        if len(fields) != 2:
            raise UmzugError("resolv.conf contains an ambiguous nameserver entry")
        add(fields[1], interface=None, origin="resolv.conf")

    unique = {(row["address"], row["scope"], row["interface"], row["origin"]): row for row in sources}
    result = [
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: tuple(part or "" for part in item),
        )
    ]
    if not result:
        raise UmzugError("no literal effective DNS resolver could be established")
    return result


def verify_effective_dns_routes(
    *,
    resolvectl_status: str | None,
    resolv_conf: str,
    wireguard_interfaces: str,
    route_evidence: object,
    ethernet_interfaces: Iterable[str],
) -> None:
    """require every effective resolver to route only via loopback or WireGuard."""

    physical = set(validate_interfaces(ethernet_interfaces))
    tunnel_interfaces = wireguard_interfaces.split()
    if (
        not tunnel_interfaces
        or len(tunnel_interfaces) != len(set(tunnel_interfaces))
        or any(not IFACE_RE.fullmatch(name) for name in tunnel_interfaces)
    ):
        raise UmzugError("effective WireGuard interface evidence is absent or malformed")
    tunnels = set(tunnel_interfaces)
    sources = parse_effective_dns_sources(resolvectl_status, resolv_conf)
    if not any(not ipaddress.ip_address(str(source["address"])).is_loopback for source in sources):
        raise UmzugError("effective DNS evidence exposes only a loopback stub without its upstream route")
    for source in sources:
        associated = {source.get("interface"), source.get("scope")} - {None}
        if associated & physical:
            raise UmzugError("an effective DNS resolver is bound to physical Ethernet")
        try:
            source_address = ipaddress.ip_address(str(source["address"]))
        except ValueError as exc:
            raise UmzugError("effective DNS resolver source is malformed") from exc
        allowed_interfaces = {"lo"} if source_address.is_loopback else tunnels
        if associated - allowed_interfaces:
            raise UmzugError("an effective DNS resolver is bound outside loopback or WireGuard")

    if not isinstance(route_evidence, dict) or set(route_evidence) != {
        "available",
        "sources",
        "lookups",
    }:
        raise UmzugError("effective DNS route evidence is absent or malformed")
    if route_evidence.get("available") is not True or route_evidence.get("sources") != sources:
        raise UmzugError("effective DNS resolver evidence changed during collection")
    lookups = route_evidence.get("lookups")
    if not isinstance(lookups, list):
        raise UmzugError("effective DNS route lookups are absent or malformed")
    expected_addresses = sorted({str(source["address"]) for source in sources})
    if len(lookups) != len(expected_addresses):
        raise UmzugError("effective DNS route lookup set is incomplete or duplicated")
    observed_addresses: list[str] = []
    for lookup in lookups:
        if not isinstance(lookup, dict) or set(lookup) != {
            "address",
            "family",
            "uid",
            "exit",
            "stdout",
        }:
            raise UmzugError("effective DNS route lookup is malformed")
        address_text = lookup.get("address")
        if not isinstance(address_text, str):
            raise UmzugError("effective DNS route lookup address is malformed")
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise UmzugError("effective DNS route lookup address is not literal") from exc
        if lookup.get("family") != address.version or lookup.get("uid") != 0 or lookup.get("exit") != 0:
            raise UmzugError("effective DNS route lookup failed or used the wrong family")
        observed_addresses.append(address.compressed)
        try:
            payload = json.loads(str(lookup.get("stdout")))
        except (json.JSONDecodeError, TypeError) as exc:
            raise UmzugError("effective DNS route JSON is unavailable or invalid") from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise UmzugError("effective DNS route JSON is ambiguous")
        route = payload[0]
        destination = route.get("dst")
        device = route.get("dev")
        try:
            destination_ip = ipaddress.ip_address(destination)
        except (TypeError, ValueError) as exc:
            raise UmzugError("effective DNS route has an invalid destination") from exc
        if destination_ip != address or not isinstance(device, str):
            raise UmzugError("effective DNS route does not match its resolver")
        if address.is_loopback:
            if device != "lo":
                raise UmzugError("loopback DNS resolver is not routed through loopback")
        elif device not in tunnels:
            raise UmzugError("effective DNS resolver route bypasses WireGuard")
        if device in physical:
            raise UmzugError("effective DNS resolver route uses physical Ethernet")
    if sorted(observed_addresses) != expected_addresses:
        raise UmzugError("effective DNS route lookup set does not match configured resolvers")


def _nft_ifaces(names: Iterable[str]) -> str:
    return ", ".join(f'"{name}"' for name in validate_interfaces(names))


def host_firewall_rules(ethernet_interfaces: Iterable[str], *, ipv6_enabled: bool) -> str:
    """independent host ingress firewall. it deliberately exposes no service."""
    interfaces = _nft_ifaces(ethernet_interfaces)
    ipv6_rules = ""
    if ipv6_enabled:
        ipv6_rules = """
        meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
        iifname @ethernet_ifaces udp sport 547 udp dport 546 accept
"""
    return f"""# Managed by umzug. No inbound SSH or application port is allowed.
# The declare+flush+populate sequence is one nft transaction. It creates the
# exclusively owned table on first use and replaces its contents on every reload.
table inet umzug_host
flush table inet umzug_host

table inet umzug_host {{
    set ethernet_ifaces {{
        type ifname
        elements = {{ {interfaces} }}
    }}

    chain input {{
        type filter hook input priority -50; policy drop;
        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        meta l4proto icmp icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
        iifname @ethernet_ifaces udp sport 67 udp dport 68 accept
{ipv6_rules.rstrip()}
    }}

    chain forward {{
        type filter hook forward priority -50; policy drop;
    }}
}}
"""


def manual_wireguard_killswitch_rules(
    ethernet_interfaces: Iterable[str],
    *,
    tunnel_interface: str,
    endpoint_ip: str,
    endpoint_port: int,
    endpoint_protocol: str = "udp",
    allow_lan: bool = False,
) -> str:
    """persistent fail-closed nftables egress policy for vanilla WireGuard.

    the relay must be a literal current IP from an explicitly approved
    configuration. existing physical-interface flows are not grandfathered.
    """
    interfaces = _nft_ifaces(ethernet_interfaces)
    if not IFACE_RE.fullmatch(tunnel_interface):
        raise UmzugError("invalid tunnel interface")
    try:
        endpoint = ipaddress.ip_address(endpoint_ip)
    except ValueError as exc:
        raise UmzugError("WireGuard endpoint must be a literal IP address") from exc
    if not 1 <= endpoint_port <= 65535 or endpoint_protocol != "udp":
        raise UmzugError("invalid WireGuard endpoint")
    family = "ip" if endpoint.version == 4 else "ip6"
    dhcp = (
        """
        oifname @ethernet_ifaces ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
"""
        if endpoint.version == 4
        else ""
    )
    lan = ""
    if allow_lan:
        lan = """
        oifname @ethernet_ifaces ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
"""
    return f"""# Managed by umzug. Persistent fail-closed policy for manual WireGuard.
# DNS is permitted only through {tunnel_interface}; the sole clear-net exception
# is the exact approved first-hop relay plus DHCPv4 when applicable.
table inet umzug_vpn_lock {{
    set ethernet_ifaces {{
        type ifname
        elements = {{ {interfaces} }}
    }}

    chain output {{
        type filter hook output priority -100; policy drop;
        oifname "lo" accept
        ct state invalid drop
        oifname "{tunnel_interface}" accept
        oifname @ethernet_ifaces {family} daddr {endpoint.compressed} {endpoint_protocol} dport {endpoint_port} accept
{dhcp.rstrip()}
{lan.rstrip()}
    }}
}}
"""


def firewall_systemd_unit(rules_path: str) -> str:
    return f"""[Unit]
Description=umzug host and VPN firewall
DefaultDependencies=no
After=local-fs.target
Before=basic.target network-pre.target network.target network-online.target mullvad-daemon.service wg-quick.target
OnFailure=emergency.target
OnFailureJobMode=isolate

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=nft -f {rules_path}
ExecReload=nft -f {rules_path}

[Install]
RequiredBy=basic.target network-pre.target network.target network-online.target mullvad-daemon.service wg-quick.target
"""


def offline_guard_rules() -> str:
    return f"""# Managed by umzug. Removed only by the explicit VPN finalizer.
table inet {OFFLINE_GUARD_TABLE}
flush table inet {OFFLINE_GUARD_TABLE}

table inet {OFFLINE_GUARD_TABLE} {{
    chain output {{
        type filter hook output priority -400; policy drop;
        oifname "lo" accept
    }}
}}
"""


def offline_guard_systemd_unit(rules_path: str) -> str:
    return f"""[Unit]
Description=umzug offline setup egress guard
DefaultDependencies=no
After=local-fs.target
Before=basic.target network-pre.target network.target network-online.target mullvad-daemon.service
OnFailure=emergency.target
OnFailureJobMode=isolate

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=nft -f {rules_path}
ExecReload=nft -f {rules_path}

[Install]
RequiredBy=basic.target network-pre.target network.target network-online.target mullvad-daemon.service
"""


def recovery_script() -> str:
    return """#!/bin/sh
# Local-console emergency recovery. This intentionally opens egress but still
# does not start sshd or create any inbound firewall exception.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin
LANG=C.UTF-8
LC_ALL=C.UTF-8
export PATH LANG LC_ALL

fail() {
    echo "umzug network recovery: $*" >&2
    exit 1
}

[ "$(id -u)" = 0 ] || fail 'must run as root'
[ "${UMZUG_INVOCATION_REMOTE:-0}" != 1 ] || fail 'remote invocation marker is set'
[ -z "${SSH_CLIENT:-}" ] && [ -z "${SSH_CONNECTION:-}" ] && [ -z "${SSH_TTY:-}" ] \
    || fail 'SSH session variables are present'
[ -t 0 ] && [ -t 1 ] || fail 'stdin and stdout must both be attached to a local console TTY'
console_tty=$(tty <&0) || fail 'cannot identify the invoking TTY'
case "$console_tty" in
    /dev/console) ;;
    /dev/ttyS*) console_suffix=${console_tty#/dev/ttyS} ;;
    /dev/tty*) console_suffix=${console_tty#/dev/tty} ;;
    /dev/hvc*) console_suffix=${console_tty#/dev/hvc} ;;
    *) fail 'TTY is not /dev/console, /dev/ttyN, /dev/ttySN, or /dev/hvcN' ;;
esac
if [ "$console_tty" != /dev/console ]; then
    case "$console_suffix" in
        ''|*[!0-9]*) fail 'local-console TTY suffix is not numeric' ;;
    esac
fi

# Inspect the complete parent chain as a second, independent remote-session
# signal. Any unreadable or malformed procfs record fails closed.
ancestor=$PPID
ancestor_steps=0
while [ "$ancestor" -gt 1 ]; do
    [ "$ancestor_steps" -lt 64 ] || fail 'process ancestry exceeds the inspection bound'
    IFS= read -r ancestor_name < "/proc/$ancestor/comm" \
        || fail 'cannot inspect process ancestry'
    case "$ancestor_name" in
        sshd*|dropbear|mosh-server|teleport|tmate) fail "remote-session ancestor detected: $ancestor_name" ;;
    esac
    next_ancestor=
    while IFS=: read -r status_key status_value; do
        if [ "$status_key" = PPid ]; then
            set -- $status_value
            next_ancestor=${1:-}
            break
        fi
    done < "/proc/$ancestor/status" || fail 'cannot inspect process ancestry status'
    case "$next_ancestor" in
        ''|*[!0-9]*) fail 'process ancestry is incomplete' ;;
    esac
    [ "$next_ancestor" != "$ancestor" ] || fail 'process ancestry contains a loop'
    ancestor=$next_ancestor
    ancestor_steps=$((ancestor_steps + 1))
done

if [ -d /run/systemd/system ]; then
    SYSTEMCTL=$(command -v systemctl) || fail 'systemd is running but systemctl is unavailable'
    "$SYSTEMCTL" daemon-reload || fail 'systemd daemon-reload failed'
    for unit in umzug-firewall.service umzug-radio-off.service umzug-offline-guard.service; do
        load_state=$("$SYSTEMCTL" show --property=LoadState --value "$unit") \
            || fail "cannot inspect $unit"
        if [ "$load_state" != not-found ]; then
            case "$load_state" in loaded|masked) ;; *) fail "$unit has an unsafe load state: $load_state" ;; esac
            "$SYSTEMCTL" disable --now "$unit" || fail "cannot disable and stop $unit"
            active_state=$("$SYSTEMCTL" show --property=ActiveState --value "$unit") \
                || fail "cannot verify active state for $unit"
            unit_file_state=$("$SYSTEMCTL" show --property=UnitFileState --value "$unit") \
                || fail "cannot verify enablement state for $unit"
            case "$active_state" in inactive|failed) ;; *) fail "$unit remains active: $active_state" ;; esac
            case "$unit_file_state" in
                disabled|masked|masked-runtime|static|indirect|generated|transient|linked|linked-runtime) ;;
                *) fail "$unit remains enabled or has an ambiguous unit-file state: $unit_file_state" ;;
            esac
        fi
    done
fi

for hook in /etc/local.d/umzug-firewall.start /etc/local.d/umzug-radio-off.start /etc/local.d/umzug-offline-guard.start; do
    disabled_hook=$hook.disabled-by-recovery
    if [ -e "$hook" ] || [ -L "$hook" ]; then
        disabled_index=0
        while [ -e "$disabled_hook" ] || [ -L "$disabled_hook" ]; do
            disabled_index=$((disabled_index + 1))
            [ "$disabled_index" -le 32 ] || fail "no unused recovery archive remains for OpenRC hook: $hook"
            disabled_hook=$hook.disabled-by-recovery.$disabled_index
        done
        mv -n "$hook" "$disabled_hook" || fail "cannot disable OpenRC hook: $hook"
    fi
    [ ! -e "$hook" ] && [ ! -L "$hook" ] || fail "OpenRC hook remains active: $hook"
done

if RFKILL=$(command -v rfkill); then
    "$RFKILL" unblock all || fail 'rfkill could not unblock radios'
    rfkill_state=$("$RFKILL" list) || fail 'rfkill state cannot be verified'
    case "$rfkill_state" in *'Soft blocked: yes'*) fail 'at least one radio remains soft-blocked' ;; esac
    if [ -n "$rfkill_state" ]; then
        case "$rfkill_state" in *'Soft blocked:'*) ;; *) fail 'rfkill output is ambiguous' ;; esac
    fi
fi

NFT=$(command -v nft) || fail 'nft is unavailable; active tables cannot be disproved or removed'
nft_tables=$("$NFT" list tables) || fail 'cannot enumerate nftables tables'
nft_batch=
for table in umzug_vpn_bootstrap_guard umzug_vpn_lock umzug_host umzug_offline_guard; do
    case "
$nft_tables
" in
        *"
table inet $table
"*) nft_batch="${nft_batch}delete table inet $table
" ;;
    esac
done
if [ -n "$nft_batch" ]; then
    printf '%s' "$nft_batch" | "$NFT" --file - || fail 'atomic removal of owned nftables tables failed'
fi
nft_tables=$("$NFT" list tables) || fail 'cannot verify nftables table removal'
for table in umzug_vpn_bootstrap_guard umzug_vpn_lock umzug_host umzug_offline_guard; do
    case "
$nft_tables
" in
        *"
table inet $table
"*) fail "owned nftables table remains active: $table" ;;
    esac
done

echo 'umzug-owned network controls removed and positively verified; sshd remains disabled.'
echo 'Use setup rollback with the saved state to restore configuration files.'
"""


def _recovery_executable(name: str) -> Path | None:
    """resolve a recovery tool only from immutable, system-owned locations."""

    found = shutil.which(name, path=RECOVERY_SEARCH_PATH)
    if found is None:
        return None
    try:
        resolved = Path(found).resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise UmzugError(f"recovery executable cannot be inspected safely: {name}") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o7022
        or not os.access(resolved, os.X_OK)
    ):
        raise UmzugError(f"recovery executable is not root-owned and immutable: {name}")
    for parent in resolved.parents:
        try:
            parent_info = parent.stat()
        except OSError as exc:
            raise UmzugError(f"recovery executable parent cannot be inspected: {name}") from exc
        parent_mode = stat.S_IMODE(parent_info.st_mode)
        sticky_root = bool(parent_mode & stat.S_ISVTX) and parent_info.st_uid == 0
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or (parent_mode & 0o022 and not sticky_root)
        ):
            raise UmzugError(f"recovery executable has an unsafe writable parent: {name}")
    return resolved


def _systemd_runtime_active() -> bool:
    return Path("/run/systemd/system").is_dir()


def _unused_disabled_hook_path(hook: Path) -> Path:
    candidates = [hook.with_name(hook.name + ".disabled-by-recovery")]
    candidates.extend(hook.with_name(hook.name + f".disabled-by-recovery.{index}") for index in range(1, 33))
    for candidate in candidates:
        if not os.path.lexists(candidate):
            return candidate
    raise UmzugError(f"no unused recovery archive remains for OpenRC hook: {hook}")


def _recovery_run(
    executable: Path,
    arguments: list[str],
    results: dict[str, int],
    *,
    input_bytes: bytes | None = None,
) -> Any:
    argv = [str(executable), *arguments]
    completed = run(argv, check=False, input_bytes=input_bytes)
    label = " ".join([executable.name, *arguments])
    results[label] = completed.returncode
    if completed.returncode != 0:
        raise UmzugError(f"network recovery command failed: {label} (exit {completed.returncode})")
    return completed


def _short_recovery_output(completed: Any, label: str) -> str:
    output = completed.stdout
    if not isinstance(output, bytes) or len(output) > 4 * 1024 * 1024:
        raise UmzugError(f"network recovery produced invalid evidence: {label}")
    try:
        return output.decode("utf-8", "strict").strip()
    except UnicodeError as exc:
        raise UmzugError(f"network recovery produced non-UTF-8 evidence: {label}") from exc


def _list_owned_nft_tables(nft: Path, results: dict[str, int]) -> set[str]:
    completed = _recovery_run(nft, ["--json", "list", "tables"], results)
    raw = _short_recovery_output(completed, "nft list tables")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UmzugError("nft table inventory is not valid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {"nftables"} or not isinstance(payload["nftables"], list):
        raise UmzugError("nft table inventory has an ambiguous structure")
    present: set[str] = set()
    for row in payload["nftables"]:
        if not isinstance(row, dict) or len(row) != 1:
            raise UmzugError("nft table inventory contains a malformed row")
        if "metainfo" in row:
            if not isinstance(row["metainfo"], dict):
                raise UmzugError("nft table inventory metadata is malformed")
            continue
        table = row.get("table")
        if not isinstance(table, dict):
            raise UmzugError("nft table inventory contains an unexpected object")
        family = table.get("family")
        name = table.get("name")
        if not isinstance(family, str) or not isinstance(name, str):
            raise UmzugError("nft table identity is malformed")
        if family == "inet" and name in OWNED_NFT_TABLES:
            present.add(name)
    return present


def _systemd_property(
    systemctl: Path,
    unit: str,
    property_name: str,
    results: dict[str, int],
) -> str:
    completed = _recovery_run(
        systemctl,
        ["show", f"--property={property_name}", "--value", unit],
        results,
    )
    value = _short_recovery_output(completed, f"systemctl {property_name}")
    if not value or len(value) > 128 or "\n" in value or any(ord(char) < 0x20 for char in value):
        raise UmzugError(f"systemd returned ambiguous {property_name} evidence for {unit}")
    return value


def recover_network(*, audit: AuditLog | None = None, dry_run: bool = False) -> dict[str, Any]:
    """disable only umzug-owned network controls and prove the postcondition."""

    audit = audit or AuditLog(None)
    if not dry_run:
        require_proven_local_console("recover-network")
    require_root(dry_run=dry_run)
    if dry_run:
        result: dict[str, Any] = {
            "status": "dry-run",
            "authorization_to_mutate": False,
            "owned_systemd_units": list(OWNED_SYSTEMD_UNITS),
            "owned_openrc_hooks": [str(path) for path in OWNED_OPENRC_HOOKS],
            "owned_nft_tables": list(OWNED_NFT_TABLES),
            "radio_unblock": "would-run-if-rfkill-is-available",
        }
        audit.event("network.recovery_dry_run", result=result)
        return result

    results: dict[str, int] = {}
    report: dict[str, Any] = {"status": "in-progress", "commands": results}
    try:
        systemd_running = _systemd_runtime_active()
        systemctl = _recovery_executable("systemctl")
        if systemd_running and systemctl is None:
            raise UmzugError("systemd is running but systemctl is unavailable; unit state cannot be proven")
        systemd_report: dict[str, str] = {}
        if systemd_running:
            assert systemctl is not None
            _recovery_run(systemctl, ["daemon-reload"], results)
            for unit in OWNED_SYSTEMD_UNITS:
                load_state = _systemd_property(systemctl, unit, "LoadState", results)
                if load_state == "not-found":
                    systemd_report[unit] = "absent"
                    continue
                if load_state not in {"loaded", "masked"}:
                    raise UmzugError(f"owned systemd unit has an unsafe load state: {unit}: {load_state}")
                _recovery_run(systemctl, ["disable", "--now", unit], results)
                active_state = _systemd_property(systemctl, unit, "ActiveState", results)
                unit_file_state = _systemd_property(systemctl, unit, "UnitFileState", results)
                if active_state not in {"inactive", "failed"}:
                    raise UmzugError(f"owned systemd unit remains active: {unit}: {active_state}")
                if unit_file_state not in {
                    "disabled",
                    "masked",
                    "masked-runtime",
                    "static",
                    "indirect",
                    "generated",
                    "transient",
                    "linked",
                    "linked-runtime",
                }:
                    raise UmzugError(f"owned systemd unit remains enabled or ambiguous: {unit}: {unit_file_state}")
                systemd_report[unit] = f"{active_state}/{unit_file_state}"
        else:
            systemd_report["runtime"] = "systemd-not-running"
        report["systemd"] = systemd_report

        hook_report: dict[str, str] = {}
        for hook in OWNED_OPENRC_HOOKS:
            active_exists = os.path.lexists(hook)
            if active_exists:
                disabled = _unused_disabled_hook_path(hook)
                parent_fd = -1
                try:
                    parent_fd = os.open(
                        hook.parent,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                    )
                    parent_info = os.fstat(parent_fd)
                    if (
                        not stat.S_ISDIR(parent_info.st_mode)
                        or parent_info.st_uid != os.geteuid()
                        or stat.S_IMODE(parent_info.st_mode) & 0o022
                    ):
                        raise UmzugError(
                            f"OpenRC hook directory is not owned by the recovery user and immutable: {hook.parent}"
                        )
                    rename_noreplace_at(parent_fd, hook.name, parent_fd, disabled.name)
                except OSError as exc:
                    raise UmzugError(f"cannot disable OpenRC hook: {hook}") from exc
                finally:
                    if parent_fd >= 0:
                        os.close(parent_fd)
                results[f"rename {hook} {disabled}"] = 0
            if os.path.lexists(hook):
                raise UmzugError(f"OpenRC hook remains active after recovery: {hook}")
            disabled_paths = [
                hook.with_name(hook.name + ".disabled-by-recovery"),
                *(hook.with_name(hook.name + f".disabled-by-recovery.{index}") for index in range(1, 33)),
            ]
            archives = [str(path) for path in disabled_paths if os.path.lexists(path)]
            hook_report[str(hook)] = "disabled:" + ",".join(archives) if archives else "absent"
        report["openrc_hooks"] = hook_report

        rfkill = _recovery_executable("rfkill")
        if rfkill is None:
            report["rfkill"] = "unavailable-no-radio-state-changed"
        else:
            _recovery_run(rfkill, ["unblock", "all"], results)
            completed = _recovery_run(rfkill, ["list"], results)
            rfkill_state = _short_recovery_output(completed, "rfkill list")
            soft_states = re.findall(r"(?im)^\s*Soft blocked:\s*(yes|no)\s*$", rfkill_state)
            if rfkill_state and not soft_states:
                raise UmzugError("rfkill state is ambiguous after recovery")
            if any(value.lower() != "no" for value in soft_states):
                raise UmzugError("at least one radio remains soft-blocked after recovery")
            report["rfkill"] = "all-observed-radios-soft-unblocked"

        nft = _recovery_executable("nft")
        if nft is None:
            raise UmzugError("nft is unavailable; active umzug tables cannot be disproved or removed")
        before = _list_owned_nft_tables(nft, results)
        if before:
            batch = "".join(f"delete table inet {name}\n" for name in OWNED_NFT_TABLES if name in before)
            _recovery_run(nft, ["--file", "-"], results, input_bytes=batch.encode("ascii"))
        remaining = _list_owned_nft_tables(nft, results)
        if remaining:
            raise UmzugError("owned nftables tables remain active: " + ", ".join(sorted(remaining)))
        report["nftables"] = {
            "removed": sorted(before),
            "verified_absent": list(OWNED_NFT_TABLES),
        }

        report["status"] = "verified"
        report["authorization_to_rollback"] = True
        audit.event("network.recovery_verified", result=report)
        return report
    except (OSError, UmzugError, ValueError) as exc:
        report["status"] = "failed"
        audit.event("network.recovery_failed", result=report, error=str(exc))
        raise


def collect_network_evidence(*, include_online_check: bool = False) -> dict[str, Any]:
    """collect proof of effective local state. network is touched only if opted in."""
    commands: dict[str, list[str]] = {
        "nft_ruleset": ["nft", "-a", "list", "ruleset"],
        "nft_host_json": ["nft", "--json", "list", "table", "inet", "umzug_host"],
        "nft_mullvad_json": ["nft", "--json", "list", "table", "inet", MULLVAD_TABLE],
        "nft_offline_guard_json": ["nft", "--json", "list", "table", "inet", OFFLINE_GUARD_TABLE],
        "nft_bootstrap_guard_json": ["nft", "--json", "list", "table", "inet", "umzug_vpn_bootstrap_guard"],
        "ip_rules_v4": ["ip", "-4", "rule", "show"],
        "ip_routes_v4": ["ip", "-4", "route", "show", "table", "all"],
        "ip_rules_v6": ["ip", "-6", "rule", "show"],
        "ip_routes_v6": ["ip", "-6", "route", "show", "table", "all"],
        "ip_links": ["ip", "-details", "link", "show"],
        "listeners": ["ss", "-lntup"],
        "ssh_service": ["systemctl", "is-active", "ssh.service"],
        "sshd_service": ["systemctl", "is-active", "sshd.service"],
        "ssh_socket": ["systemctl", "is-active", "ssh.socket"],
        "sshd_socket": ["systemctl", "is-active", "sshd.socket"],
        "rfkill": ["rfkill", "list"],
        "mullvad": ["mullvad", "status", "-v"],
        "mullvad_lockdown": ["mullvad", "lockdown-mode", "get"],
        "mullvad_dns": ["mullvad", "dns", "get"],
        "mullvad_daemon_enabled": ["systemctl", "is-enabled", "mullvad-daemon.service"],
        "mullvad_daemon_active": ["systemctl", "is-active", "mullvad-daemon.service"],
        "wireguard": ["wg", "show"],
        "dns": ["resolvectl", "status"],
    }
    evidence: dict[str, Any] = {}
    for name, argv in commands.items():
        if which(argv[0]) is None:
            evidence[name] = {"available": False}
            continue
        completed = run(argv, check=False, timeout=30)
        text = completed.stdout.decode("utf-8", errors="replace")
        evidence[name] = {
            "available": True,
            "exit": completed.returncode,
            "stdout": text[:2_000_000],
        }
    ipv6_sysctls: dict[str, str | None] = {}
    for name in ("all", "default", "lo"):
        path = Path(f"/proc/sys/net/ipv6/conf/{name}/disable_ipv6")
        try:
            ipv6_sysctls[name] = path.read_text(encoding="ascii").strip()[:16]
        except (OSError, UnicodeError):
            ipv6_sysctls[name] = None
    try:
        ipv6_addresses = Path("/proc/net/if_inet6").read_text(encoding="ascii")[:2_000_000]
    except (OSError, UnicodeError):
        ipv6_addresses = None
    evidence["ipv6_state"] = {
        "sysctls": ipv6_sysctls,
        "addresses": ipv6_addresses,
    }
    try:
        resolv_conf = Path("/etc/resolv.conf").read_text(encoding="utf-8")[:1_000_000]
    except (OSError, UnicodeError):
        resolv_conf = None
    evidence["resolv_conf"] = {"content": resolv_conf}
    if include_online_check:
        if which("curl") is None:
            evidence["mullvad_online"] = {"available": False}
        else:
            completed = run(
                [
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "15",
                    "https://am.i.mullvad.net/connected",
                ],
                check=False,
                timeout=20,
            )
            evidence["mullvad_online"] = {
                "available": True,
                "exit": completed.returncode,
                "stdout": completed.stdout.decode(errors="replace")[:1000],
            }
    return evidence


def _mullvad_online_response_is_positive(value: object) -> bool:
    """fail closed on mullvad's human-readable connection endpoint."""

    if not isinstance(value, str):
        return False
    normalized = " ".join(value.strip().lower().split())
    return normalized.startswith("you are connected to mullvad") and "not connected" not in normalized


def _mullvad_cli_status_is_connected(value: object) -> bool:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return False
    lines = [line.strip().lower() for line in value.splitlines() if line.strip()]
    if not lines:
        return False
    return lines[0] == "connected" or lines[0].startswith("connected to ")


def _mullvad_cli_status_is_disconnected(value: object) -> bool:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return False
    lines = [line.strip().lower() for line in value.splitlines() if line.strip()]
    if not lines:
        return False
    return re.match(r"^(?:disconnected|blocked)(?:[\s;:,.]|$)", lines[0]) is not None


def _mullvad_setting_is_on(value: object) -> bool:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return False
    normalized = " ".join(value.strip().lower().split())
    return normalized == "on" or normalized.endswith(" is on")


def _nft_objects(payload: bytes | str, *, label: str) -> list[tuple[str, dict[str, Any]]]:
    """parse the deliberately small, typed subset used by nft list JSON."""

    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise UmzugError(f"{label} nftables JSON is unavailable or invalid") from exc
    rows = document.get("nftables") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        raise UmzugError(f"{label} nftables JSON has no rule list")
    result: list[tuple[str, dict[str, Any]]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or len(row) != 1:
            raise UmzugError(f"{label} nftables object {index} is malformed")
        kind, value = next(iter(row.items()))
        if kind == "metainfo":
            if not isinstance(value, dict):
                raise UmzugError(f"{label} nftables metainfo is malformed")
            continue
        if not isinstance(kind, str) or not isinstance(value, dict):
            raise UmzugError(f"{label} nftables object {index} is malformed")
        result.append((kind, value))
    return result


def _require_nft_keys(
    value: dict[str, Any],
    *,
    required: set[str],
    optional: set[str] | frozenset[str] = frozenset(),
    label: str,
) -> None:
    keys = set(value)
    missing = required - keys
    unexpected = keys - required - set(optional)
    if missing or unexpected:
        raise UmzugError(
            f"{label} has missing or unexpected fields: missing={sorted(missing)}, unexpected={sorted(unexpected)}"
        )


def _normalise_nft_ast(value: Any) -> tuple[Any, ...] | str | int | None:
    """return a hashable semantic form while preserving statement/list order.

    anonymous nft sets are mathematical sets, so their element order is not
    significant. rule statement order and all other arrays remain exact.
    equality and membership operators are normalised only for operands which
    nft serialises differently on supported releases.
    """

    if value is None or isinstance(value, str):
        return value
    if type(value) is int:
        return value
    if isinstance(value, bool):
        return ("bool", int(value))
    if isinstance(value, list):
        return ("list", *(_normalise_nft_ast(item) for item in value))
    if not isinstance(value, dict):
        raise UmzugError("nftables expression contains an unsupported JSON value")
    if set(value) == {"set"}:
        members = value["set"]
        if not isinstance(members, list):
            raise UmzugError("nftables anonymous set is not an array")
        normalised = [_normalise_nft_ast(item) for item in members]
        if len(set(normalised)) != len(normalised):
            raise UmzugError("nftables anonymous set contains duplicate elements")
        return ("set", *sorted(normalised, key=repr))
    if set(value) == {"match"}:
        match = value["match"]
        if not isinstance(match, dict) or set(match) != {"op", "left", "right"}:
            raise UmzugError("nftables match expression is malformed")
        operator = match["op"]
        left = match["left"]
        right = match["right"]
        membership = (
            (isinstance(right, dict) and set(right) == {"set"})
            or (isinstance(right, str) and right.startswith("@"))
            or left == {"ct": {"key": "state"}}
        )
        if membership and operator in {"==", "in"}:
            operator = "membership"
        if operator not in {"==", "!=", "membership"}:
            raise UmzugError("nftables match uses an unsupported operator")
        return (
            "match",
            operator,
            _normalise_nft_ast(left),
            _normalise_nft_ast(right),
        )
    return (
        "object",
        *((str(key), _normalise_nft_ast(child)) for key, child in sorted(value.items())),
    )


def _match(left: dict[str, Any], right: Any, *, operator: str = "==") -> dict[str, Any]:
    return {"match": {"op": operator, "left": left, "right": right}}


def _expected_host_input_rules(*, ipv6_enabled: bool) -> list[Any]:
    rules: list[list[dict[str, Any]]] = [
        [_match({"meta": {"key": "iifname"}}, "lo"), {"accept": None}],
        [_match({"ct": {"key": "state"}}, "invalid", operator="in"), {"drop": None}],
        [
            _match(
                {"ct": {"key": "state"}},
                {"set": ["established", "related"]},
                operator="in",
            ),
            {"accept": None},
        ],
        [
            _match({"meta": {"key": "l4proto"}}, "icmp"),
            _match(
                {"payload": {"protocol": "icmp", "field": "type"}},
                {"set": ["destination-unreachable", "time-exceeded", "parameter-problem"]},
                operator="in",
            ),
            {"accept": None},
        ],
        [
            _match({"meta": {"key": "iifname"}}, "@ethernet_ifaces", operator="in"),
            _match({"payload": {"protocol": "udp", "field": "sport"}}, 67),
            _match({"payload": {"protocol": "udp", "field": "dport"}}, 68),
            {"accept": None},
        ],
    ]
    if ipv6_enabled:
        rules.extend(
            [
                [
                    _match({"meta": {"key": "l4proto"}}, "ipv6-icmp"),
                    _match(
                        {"payload": {"protocol": "icmpv6", "field": "type"}},
                        {
                            "set": [
                                "destination-unreachable",
                                "packet-too-big",
                                "time-exceeded",
                                "parameter-problem",
                                "nd-neighbor-solicit",
                                "nd-neighbor-advert",
                                "nd-router-advert",
                            ]
                        },
                        operator="in",
                    ),
                    {"accept": None},
                ],
                [
                    _match(
                        {"meta": {"key": "iifname"}},
                        "@ethernet_ifaces",
                        operator="in",
                    ),
                    _match({"payload": {"protocol": "udp", "field": "sport"}}, 547),
                    _match({"payload": {"protocol": "udp", "field": "dport"}}, 546),
                    {"accept": None},
                ],
            ]
        )
    return [_normalise_nft_ast(rule) for rule in rules]


def _terminal_verdict(expression: Any) -> tuple[str | None, bool]:
    """return the terminal verdict and whether a packet selector precedes it."""

    if not isinstance(expression, list) or not expression:
        raise UmzugError("nftables rule expression is absent or malformed")
    verdict: str | None = None
    verdict_index = -1
    has_selector = False
    for index, statement in enumerate(expression):
        if not isinstance(statement, dict) or len(statement) != 1:
            raise UmzugError("nftables rule statement is malformed")
        kind, value = next(iter(statement.items()))
        if kind in {"jump", "goto", "return", "continue", "queue", "vmap"}:
            raise UmzugError("nftables rule uses indirect or userspace-controlled verdict flow")
        if kind in {"match", "lookup", "limit", "quota"}:
            has_selector = True
        if kind in {"accept", "drop", "reject"}:
            if (value is not None and value is not False) or verdict is not None:
                raise UmzugError("nftables rule has an ambiguous terminal verdict")
            verdict = kind
            verdict_index = index
        _normalise_nft_ast(statement)
    if verdict is not None and verdict_index != len(expression) - 1:
        raise UmzugError("nftables terminal verdict is not the final statement")
    return verdict, has_selector


def _literal_match_members(value: Any) -> set[str | int] | None:
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return {value}
    if isinstance(value, dict) and set(value) == {"set"} and isinstance(value["set"], list):
        members: set[str | int] = set()
        for item in value["set"]:
            if not isinstance(item, (str, int)) or isinstance(item, bool):
                return None
            members.add(item)
        return members
    return None


def _match_field(
    statement: object,
    expected_left: object,
) -> tuple[str, set[str | int] | None] | None:
    if not isinstance(statement, dict) or set(statement) != {"match"}:
        return None
    match = statement["match"]
    if not isinstance(match, dict) or set(match) != {"op", "left", "right"}:
        return None
    if _normalise_nft_ast(match["left"]) != _normalise_nft_ast(expected_left):
        return None
    operator = match["op"]
    if not isinstance(operator, str):
        return None
    return operator, _literal_match_members(match["right"])


def _constraint_excludes_dns_port(
    operator: str,
    members: set[str | int] | None,
) -> bool:
    if members is None:
        return False
    numeric: set[int] = set()
    for member in members:
        try:
            port = int(member)
        except (TypeError, ValueError):
            return False
        if not 0 <= port <= 65535:
            return False
        numeric.add(port)
    if operator in {"==", "in"}:
        return 53 not in numeric
    if operator in {"!=", "not in"}:
        return numeric == {53}
    if len(numeric) != 1:
        return False
    boundary = next(iter(numeric))
    return (
        (operator == "<" and 53 >= boundary)
        or (operator == "<=" and 53 > boundary)
        or (operator == ">" and 53 <= boundary)
        or (operator == ">=" and 53 < boundary)
    )


def _rule_explicitly_allows_physical_dns(
    expression: object,
    ethernet_interfaces: set[str],
) -> bool:
    if not isinstance(expression, list):
        return False
    physical_oif = False
    dns_port_excluded = False
    dns_protocol_excluded = False
    for statement in expression:
        interface_match = _match_field(statement, {"meta": {"key": "oifname"}})
        if interface_match is not None:
            operator, members = interface_match
            if operator in {"==", "in"} and members is not None:
                physical_oif = (
                    physical_oif
                    or bool(ethernet_interfaces & {str(member) for member in members})
                    or "@ethernet_ifaces" in members
                )
        for left in (
            {"payload": {"protocol": "udp", "field": "dport"}},
            {"payload": {"protocol": "tcp", "field": "dport"}},
            {"payload": {"protocol": "th", "field": "dport"}},
        ):
            port_match = _match_field(statement, left)
            if port_match is not None and _constraint_excludes_dns_port(*port_match):
                dns_port_excluded = True
        protocol_match = _match_field(statement, {"meta": {"key": "l4proto"}})
        if protocol_match is not None:
            operator, members = protocol_match
            if operator in {"==", "in"} and members is not None:
                dns_protocol_excluded = dns_protocol_excluded or not bool({"udp", "tcp"} & members)
            elif operator in {"!=", "not in"} and members == {"udp", "tcp"}:
                dns_protocol_excluded = True
    verdict, _selected = _terminal_verdict(expression)
    return verdict == "accept" and physical_oif and not dns_port_excluded and not dns_protocol_excluded


def verify_mullvad_firewall_json(
    payload: bytes | str,
    *,
    ethernet_interfaces: Iterable[str] | None = None,
) -> None:
    """check only structural fail-closed properties of mullvad's dynamic table.

    this deliberately does not claim that arbitrary vendor-generated matches
    bind every accepted packet to the tunnel, constrain DNS, or prevent routing
    leaks. those properties require a version-bound vendor ruleset matcher and
    an independent disconnect/leak test. here we prove only that the output
    base chain exists, has a default blocking path, and contains no structurally
    unconditional accept rule before that path.
    """

    objects = _nft_objects(payload, label="effective Mullvad firewall")
    tables = [value for kind, value in objects if kind == "table"]
    if sum(row.get("family") == "inet" and row.get("name") == MULLVAD_TABLE for row in tables) != 1:
        raise UmzugError("effective Mullvad inet table is missing or ambiguous")
    output_chains = [
        value
        for kind, value in objects
        if kind == "chain"
        and value.get("family") == "inet"
        and value.get("table") == MULLVAD_TABLE
        and value.get("name") == "output"
        and value.get("hook") == "output"
    ]
    if len(output_chains) != 1 or output_chains[0].get("type") not in {"filter", "route"}:
        raise UmzugError("effective Mullvad output base chain is missing or ambiguous")
    chain = output_chains[0]
    if type(chain.get("prio")) is not int or chain.get("policy") != "drop":
        raise UmzugError("effective Mullvad output base chain has an invalid priority or policy")
    output_rules = [
        value
        for kind, value in objects
        if kind == "rule"
        and value.get("family") == "inet"
        and value.get("table") == MULLVAD_TABLE
        and value.get("chain") == "output"
    ]
    if not output_rules:
        raise UmzugError("effective Mullvad output chain has no rules")
    analysed = [_terminal_verdict(rule.get("expr")) for rule in output_rules]
    if any(verdict == "accept" and not selected for verdict, selected in analysed):
        raise UmzugError("effective Mullvad output chain contains an unconditional accept rule")
    if ethernet_interfaces is not None:
        physical = set(validate_interfaces(ethernet_interfaces))
        if any(_rule_explicitly_allows_physical_dns(rule.get("expr"), physical) for rule in output_rules):
            raise UmzugError("effective Mullvad output chain directly accepts DNS on physical Ethernet")
    # the current official linux implementation creates the output base chain
    # with policy::drop.  a later unconditional reject is not an equivalent
    # invariant: return/queue/indirect verdict paths could bypass it.


def assert_final_network_evidence(
    evidence: dict[str, Any],
    ethernet_interfaces: Iterable[str],
    *,
    ipv6_disabled: bool,
    radios_blocked: bool,
    online_verification: bool,
) -> None:
    """validate the final point-in-time network state without trusting prose."""

    interfaces = validate_interfaces(ethernet_interfaces)

    def record(name: str, *, success: bool = True) -> dict[str, Any]:
        value = evidence.get(name)
        if not isinstance(value, dict) or value.get("available") is not True:
            raise UmzugError(f"required final network evidence is unavailable: {name}")
        if success and value.get("exit") != 0:
            raise UmzugError(f"required final network evidence command failed: {name}")
        return value

    host = record("nft_host_json")
    verify_host_firewall_json(host.get("stdout", ""), interfaces, ipv6_enabled=not ipv6_disabled)
    mullvad_table = record("nft_mullvad_json")
    verify_mullvad_firewall_json(
        mullvad_table.get("stdout", ""),
        ethernet_interfaces=interfaces,
    )
    for stale_guard in ("nft_offline_guard_json", "nft_bootstrap_guard_json"):
        if record(stale_guard, success=False).get("exit") == 0:
            raise UmzugError(f"temporary setup guard remained active after VPN connection: {stale_guard}")

    status = record("mullvad").get("stdout")
    if not _mullvad_cli_status_is_connected(status):
        raise UmzugError("final evidence does not show a connected Mullvad tunnel")
    lockdown = record("mullvad_lockdown").get("stdout")
    if not _mullvad_setting_is_on(lockdown):
        raise UmzugError("final evidence does not show Mullvad Lockdown Mode on")
    # the finalizer has just applied `mullvad dns set default`.  requiring the
    # daemon to expose its effective DNS configuration here binds that setting
    # to the final report.  the dynamic vendor nft matcher deliberately does
    # not overclaim resolver identity; the controlled disconnect test provides
    # the independent fail-closed egress check.
    if not str(record("mullvad_dns").get("stdout", "")).strip():
        raise UmzugError("final evidence does not expose Mullvad's effective DNS configuration")
    resolv_conf_record = evidence.get("resolv_conf")
    if not isinstance(resolv_conf_record, dict) or not isinstance(resolv_conf_record.get("content"), str):
        raise UmzugError("final evidence does not expose resolv.conf")
    dns_record = evidence.get("dns")
    if not isinstance(dns_record, dict):
        raise UmzugError("final DNS link evidence is malformed")
    if dns_record.get("available") is True:
        if dns_record.get("exit") != 0 or not isinstance(dns_record.get("stdout"), str):
            raise UmzugError("receipt-bound resolvectl evidence failed or is malformed")
        resolvectl_status: str | None = str(dns_record["stdout"])
    elif dns_record == {"available": False}:
        resolvectl_status = None
    else:
        raise UmzugError("final DNS link evidence is ambiguous")
    verify_effective_dns_routes(
        resolvectl_status=resolvectl_status,
        resolv_conf=str(resolv_conf_record["content"]),
        wireguard_interfaces=str(record("wireguard_interfaces").get("stdout", "")),
        route_evidence=evidence.get("resolver_routes"),
        ethernet_interfaces=interfaces,
    )
    record("mullvad_daemon_enabled")
    record("mullvad_daemon_active")

    listeners = str(record("listeners").get("stdout", ""))
    if any(
        "sshd" in line.lower() or re.search(r"(?:^|[\]\s:])22(?:\s|$)", line) is not None
        for line in listeners.splitlines()
    ):
        raise UmzugError("final evidence shows an SSH daemon or listener on port 22")
    for unit in ("ssh_service", "sshd_service", "ssh_socket", "sshd_socket"):
        if record(unit, success=False).get("exit") == 0:
            raise UmzugError(f"final evidence shows an active incoming SSH unit: {unit}")

    if radios_blocked:
        rfkill = str(record("rfkill").get("stdout", "")).lower()
        if "soft blocked: no" in rfkill:
            raise UmzugError("final evidence shows a soft-unblocked radio")
    if ipv6_disabled:
        ipv6 = evidence.get("ipv6_state")
        if not isinstance(ipv6, dict) or ipv6.get("sysctls") != {
            "all": "1",
            "default": "1",
            "lo": "1",
        }:
            raise UmzugError("final evidence does not prove all required IPv6 sysctls")
        addresses = ipv6.get("addresses")
        if not isinstance(addresses, str) or addresses.strip():
            raise UmzugError("final evidence shows IPv6 addresses or cannot prove their absence")

    tunnel_text = "\n".join(
        str(record(name, success=False).get("stdout", "")) for name in ("mullvad", "wireguard", "ip_links")
    ).lower()
    if "wireguard" not in tunnel_text and "wg-mullvad" not in tunnel_text and "wg0-mullvad" not in tunnel_text:
        raise UmzugError("final evidence does not identify a WireGuard Mullvad tunnel")
    if online_verification:
        online = record("mullvad_online")
        if not _mullvad_online_response_is_positive(online.get("stdout")):
            raise UmzugError("Mullvad's online endpoint did not confirm the tunnel")


def assert_no_ssh_exposure(rules: str) -> None:
    lowered = re.sub(r"#.*", "", rules.lower())
    forbidden = ("tcp dport 22 accept", "tcp dport ssh accept", "dport { 22", "ssh accept")
    if any(token in lowered for token in forbidden):
        raise UmzugError("generated firewall would expose SSH")


def verify_host_firewall_json(
    payload: bytes | str,
    ethernet_interfaces: Iterable[str],
    *,
    ipv6_enabled: bool,
) -> None:
    """match the complete owned table, including every expression and its order."""

    expected_interfaces = validate_interfaces(ethernet_interfaces)
    objects = _nft_objects(payload, label="effective host firewall")
    unexpected_kinds = sorted({kind for kind, _value in objects} - {"table", "chain", "set", "rule"})
    if unexpected_kinds:
        raise UmzugError(f"effective host firewall contains unexpected object types: {unexpected_kinds}")

    tables = [value for kind, value in objects if kind == "table"]
    if len(tables) != 1:
        raise UmzugError("effective umzug_host table is missing or ambiguous")
    table = tables[0]
    _require_nft_keys(
        table,
        required={"family", "name"},
        optional={"handle"},
        label="effective host table",
    )
    if table["family"] != "inet" or table["name"] != "umzug_host":
        raise UmzugError("effective umzug_host table identity differs from the reviewed plan")

    chains = [value for kind, value in objects if kind == "chain"]
    if len(chains) != 2:
        raise UmzugError("effective host firewall has unexpected or missing chains")
    by_name: dict[str, dict[str, Any]] = {}
    for chain in chains:
        _require_nft_keys(
            chain,
            required={"family", "table", "name", "type", "hook", "prio", "policy"},
            optional={"handle"},
            label="effective host chain",
        )
        name = chain["name"]
        if not isinstance(name, str) or name in by_name:
            raise UmzugError("effective host firewall has duplicate or malformed chains")
        by_name[name] = chain
    if set(by_name) != {"input", "forward"}:
        raise UmzugError("effective host firewall has unexpected or missing chains")
    for name, hook in {"input": "input", "forward": "forward"}.items():
        chain = by_name[name]
        if (
            chain["family"] != "inet"
            or chain["table"] != "umzug_host"
            or chain["type"] != "filter"
            or chain["hook"] != hook
            or chain["policy"] != "drop"
            or type(chain["prio"]) is not int
            or chain["prio"] != -50
        ):
            raise UmzugError(f"effective {name} chain is not the required default-drop base chain")

    sets = [value for kind, value in objects if kind == "set"]
    if len(sets) != 1:
        raise UmzugError("effective Ethernet interface set is missing or ambiguous")
    interface_set = sets[0]
    _require_nft_keys(
        interface_set,
        required={"family", "table", "name", "type", "elem"},
        optional={"handle"},
        label="effective Ethernet interface set",
    )
    elements = interface_set["elem"]
    if (
        interface_set["family"] != "inet"
        or interface_set["table"] != "umzug_host"
        or interface_set["name"] != "ethernet_ifaces"
        or interface_set["type"] != "ifname"
        or not isinstance(elements, list)
        or any(not isinstance(item, str) for item in elements)
        or len(set(elements)) != len(elements)
        or sorted(elements) != expected_interfaces
    ):
        raise UmzugError("effective Ethernet interface set differs from the reviewed plan")

    rules = [value for kind, value in objects if kind == "rule"]
    observed_rules: list[Any] = []
    for rule in rules:
        _require_nft_keys(
            rule,
            required={"family", "table", "chain", "expr"},
            optional={"handle"},
            label="effective host rule",
        )
        if rule["family"] != "inet" or rule["table"] != "umzug_host" or rule["chain"] != "input":
            raise UmzugError("effective host firewall contains a rule outside input")
        observed_rules.append(_normalise_nft_ast(rule["expr"]))
    if observed_rules != _expected_host_input_rules(ipv6_enabled=ipv6_enabled):
        raise UmzugError("effective host firewall expressions or rule order differ from the reviewed plan")


def verify_loopback_guard_json(
    payload: bytes | str,
    *,
    table_name: str,
    priority: int,
) -> None:
    if not re.fullmatch(r"umzug_[a-z0-9_]+", table_name):
        raise UmzugError("invalid owned guard table name")
    objects = _nft_objects(payload, label="effective egress guard")
    unexpected_kinds = sorted({kind for kind, _value in objects} - {"table", "chain", "rule"})
    if unexpected_kinds:
        raise UmzugError(f"effective egress guard contains unexpected object types: {unexpected_kinds}")
    tables = [value for kind, value in objects if kind == "table"]
    chains = [value for kind, value in objects if kind == "chain"]
    rules = [value for kind, value in objects if kind == "rule"]
    if len(tables) != 1 or len(chains) != 1 or len(rules) != 1:
        raise UmzugError("effective egress guard has unexpected or missing objects")

    table = tables[0]
    _require_nft_keys(
        table,
        required={"family", "name"},
        optional={"handle"},
        label="effective egress guard table",
    )
    if table["family"] != "inet" or table["name"] != table_name:
        raise UmzugError("effective egress guard table identity differs from the reviewed plan")

    chain = chains[0]
    _require_nft_keys(
        chain,
        required={"family", "table", "name", "type", "hook", "prio", "policy"},
        optional={"handle"},
        label="effective egress guard chain",
    )
    if (
        chain["family"] != "inet"
        or chain["table"] != table_name
        or chain["name"] != "output"
        or chain["hook"] != "output"
        or chain["type"] != "filter"
        or chain["policy"] != "drop"
        or type(chain["prio"]) is not int
        or chain["prio"] != priority
    ):
        raise UmzugError("effective egress guard is not the reviewed output default-drop chain")

    rule = rules[0]
    _require_nft_keys(
        rule,
        required={"family", "table", "chain", "expr"},
        optional={"handle"},
        label="effective egress guard rule",
    )
    expected = _normalise_nft_ast([_match({"meta": {"key": "oifname"}}, "lo"), {"accept": None}])
    if (
        rule["family"] != "inet"
        or rule["table"] != table_name
        or rule["chain"] != "output"
        or _normalise_nft_ast(rule["expr"]) != expected
    ):
        raise UmzugError("effective egress guard differs from its sole exact loopback exception")


def verify_offline_guard_json(payload: bytes | str) -> None:
    verify_loopback_guard_json(
        payload,
        table_name=OFFLINE_GUARD_TABLE,
        priority=-400,
    )
