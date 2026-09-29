from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from umzug.network import (
    _mullvad_cli_status_is_connected,
    _mullvad_cli_status_is_disconnected,
    _mullvad_online_response_is_positive,
    _mullvad_setting_is_on,
    assert_no_ssh_exposure,
    firewall_systemd_unit,
    host_firewall_rules,
    manual_wireguard_killswitch_rules,
    offline_guard_systemd_unit,
    parse_effective_dns_sources,
    recovery_script,
    validate_interfaces,
    verify_host_firewall_json,
    verify_loopback_guard_json,
    verify_mullvad_firewall_json,
    verify_effective_dns_routes,
)
from umzug.source_media import REQUIRED_OPTIONS, _open_root_owned_mountpoint, inspect_mount
from umzug.util import UmzugError


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("You are connected to Mullvad (server se-got-wg-001).\n", True),
        ("You are not connected to Mullvad. Your IP address is 192.0.2.1\n", False),
        ("connected", False),
        ("", False),
        (None, False),
    ],
)
def test_mullvad_online_response_is_unambiguously_positive(
    response: object,
    expected: bool,
) -> None:
    assert _mullvad_online_response_is_positive(response) is expected


@pytest.mark.parametrize(
    ("response", "connected", "disconnected"),
    [
        ("Connected\nRelay: se-got-wg-001\n", True, False),
        ("Connected to se-got-wg-001\n", True, False),
        ("Disconnected\n", False, True),
        ("Blocked by lockdown mode\n", False, True),
        ("Not connected\n", False, False),
        ("Connecting\n", False, False),
    ],
)
def test_mullvad_cli_status_requires_an_exact_state_prefix(
    response: str,
    connected: bool,
    disconnected: bool,
) -> None:
    assert _mullvad_cli_status_is_connected(response) is connected
    assert _mullvad_cli_status_is_disconnected(response) is disconnected


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("Lockdown mode is on\n", True),
        ("on\n", True),
        ("Lockdown mode is off\n", False),
        ("Lockdown mode is not on\n", False),
    ],
)
def test_mullvad_lockdown_parser_rejects_ambiguous_prose(
    response: str,
    expected: bool,
) -> None:
    assert _mullvad_setting_is_on(response) is expected


def _without_comments(rules: str) -> str:
    return "\n".join(line.split("#", 1)[0].rstrip() for line in rules.splitlines())


def test_root_mountpoint_rejects_a_user_owned_parent(tmp_path: Path) -> None:
    with pytest.raises(UmzugError, match="non-root-owned or replaceable"):
        _open_root_owned_mountpoint(tmp_path / "source")


def test_offline_guard_is_a_fail_closed_boot_gate() -> None:
    unit = offline_guard_systemd_unit("/etc/umzug/offline-guard.nft")

    assert "After=local-fs.target\n" in unit
    assert (
        "Before=basic.target network-pre.target network.target network-online.target mullvad-daemon.service\n"
    ) in unit
    assert "OnFailure=emergency.target\n" in unit
    assert "OnFailureJobMode=isolate\n" in unit
    assert (
        "RequiredBy=basic.target network-pre.target network.target network-online.target mullvad-daemon.service\n"
    ) in unit
    assert "WantedBy=" not in unit


def test_host_firewall_is_a_fail_closed_boot_gate() -> None:
    unit = firewall_systemd_unit("/etc/umzug/firewall.nft")

    assert "After=local-fs.target\n" in unit
    assert (
        "Before=basic.target network-pre.target network.target "
        "network-online.target mullvad-daemon.service wg-quick.target\n"
    ) in unit
    assert "OnFailure=emergency.target\n" in unit
    assert "OnFailureJobMode=isolate\n" in unit
    assert (
        "RequiredBy=basic.target network-pre.target network.target "
        "network-online.target mullvad-daemon.service wg-quick.target\n"
    ) in unit
    assert "WantedBy=" not in unit


def _accept_rules(rules: str) -> set[str]:
    return {line.strip() for line in _without_comments(rules).splitlines() if line.strip().endswith(" accept")}


def _json_match(
    left: dict[str, object],
    right: object,
    *,
    operator: str = "==",
) -> dict[str, object]:
    return {"match": {"op": operator, "left": left, "right": right}}


def _json_rule(
    table: str,
    chain: str,
    expression: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "rule": {
            "family": "inet",
            "table": table,
            "chain": chain,
            "expr": expression,
        }
    }


def _host_firewall_json(*, ipv6_enabled: bool) -> dict[str, object]:
    input_rules = [
        [
            _json_match({"meta": {"key": "iifname"}}, "lo"),
            {"accept": None},
        ],
        [
            _json_match({"ct": {"key": "state"}}, "invalid", operator="in"),
            {"drop": None},
        ],
        [
            _json_match(
                {"ct": {"key": "state"}},
                {"set": ["related", "established"]},
                operator="in",
            ),
            {"accept": None},
        ],
        [
            _json_match({"meta": {"key": "l4proto"}}, "icmp"),
            _json_match(
                {"payload": {"protocol": "icmp", "field": "type"}},
                {"set": ["parameter-problem", "destination-unreachable", "time-exceeded"]},
                operator="in",
            ),
            {"accept": None},
        ],
        [
            _json_match(
                {"meta": {"key": "iifname"}},
                "@ethernet_ifaces",
                operator="in",
            ),
            _json_match({"payload": {"protocol": "udp", "field": "sport"}}, 67),
            _json_match({"payload": {"protocol": "udp", "field": "dport"}}, 68),
            {"accept": None},
        ],
    ]
    if ipv6_enabled:
        input_rules.extend(
            [
                [
                    _json_match({"meta": {"key": "l4proto"}}, "ipv6-icmp"),
                    _json_match(
                        {"payload": {"protocol": "icmpv6", "field": "type"}},
                        {
                            "set": [
                                "nd-router-advert",
                                "nd-neighbor-advert",
                                "nd-neighbor-solicit",
                                "parameter-problem",
                                "time-exceeded",
                                "packet-too-big",
                                "destination-unreachable",
                            ]
                        },
                        operator="in",
                    ),
                    {"accept": None},
                ],
                [
                    _json_match(
                        {"meta": {"key": "iifname"}},
                        "@ethernet_ifaces",
                        operator="in",
                    ),
                    _json_match({"payload": {"protocol": "udp", "field": "sport"}}, 547),
                    _json_match({"payload": {"protocol": "udp", "field": "dport"}}, 546),
                    {"accept": None},
                ],
            ]
        )
    rows: list[dict[str, object]] = [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": "umzug_host", "handle": 10}},
        {
            "set": {
                "family": "inet",
                "table": "umzug_host",
                "name": "ethernet_ifaces",
                "type": "ifname",
                "handle": 11,
                "elem": ["enp5s0", "eno1"],
            }
        },
        {
            "chain": {
                "family": "inet",
                "table": "umzug_host",
                "name": "input",
                "type": "filter",
                "hook": "input",
                "prio": -50,
                "policy": "drop",
                "handle": 12,
            }
        },
        {
            "chain": {
                "family": "inet",
                "table": "umzug_host",
                "name": "forward",
                "type": "filter",
                "hook": "forward",
                "prio": -50,
                "policy": "drop",
                "handle": 13,
            }
        },
    ]
    rows.extend(_json_rule("umzug_host", "input", expression) for expression in input_rules)
    return {"nftables": rows}


def _loopback_guard_json(
    *,
    table_name: str = "umzug_offline_guard",
    priority: int = -400,
) -> dict[str, object]:
    return {
        "nftables": [
            {"table": {"family": "inet", "name": table_name, "handle": 20}},
            {
                "chain": {
                    "family": "inet",
                    "table": table_name,
                    "name": "output",
                    "type": "filter",
                    "hook": "output",
                    "prio": priority,
                    "policy": "drop",
                    "handle": 21,
                }
            },
            _json_rule(
                table_name,
                "output",
                [
                    _json_match({"meta": {"key": "oifname"}}, "lo"),
                    {"accept": None},
                ],
            ),
        ]
    }


def _mullvad_json(*, policy: str = "drop") -> dict[str, object]:
    return {
        "nftables": [
            {"table": {"family": "inet", "name": "mullvad"}},
            {
                "chain": {
                    "family": "inet",
                    "table": "mullvad",
                    "name": "output",
                    "type": "filter",
                    "hook": "output",
                    "prio": -200,
                    "policy": policy,
                }
            },
            _json_rule(
                "mullvad",
                "output",
                [
                    _json_match({"meta": {"key": "oifname"}}, "wg-mullvad"),
                    {"accept": None},
                ],
            ),
            _json_rule("mullvad", "output", [{"drop": None}]),
        ]
    }


@pytest.mark.parametrize("ipv6_enabled", [False, True])
def test_host_firewall_is_fail_closed_and_never_exposes_ssh(ipv6_enabled: bool) -> None:
    rules = host_firewall_rules(["enp5s0", "eno1"], ipv6_enabled=ipv6_enabled)
    effective = _without_comments(rules).lower()

    assert re.search(
        r"chain\s+input\s*\{\s*type filter hook input priority -50; policy drop;",
        effective,
    )
    assert re.search(
        r"chain\s+forward\s*\{\s*type filter hook forward priority -50; policy drop;",
        effective,
    )
    assert 'elements = { "eno1", "enp5s0" }' in effective
    assert "tcp dport 22" not in effective
    assert "tcp dport ssh" not in effective
    assert_no_ssh_exposure(rules)
    if ipv6_enabled:
        assert "ipv6-icmp" in effective
        assert "udp sport 547 udp dport 546 accept" in effective
    else:
        assert "ipv6-icmp" not in effective
        assert "udp dport 546" not in effective


def test_host_firewall_ssh_guard_rejects_an_explicit_accept_rule() -> None:
    with pytest.raises(UmzugError, match="expose SSH"):
        assert_no_ssh_exposure("table inet bad { chain input { tcp dport 22 accept; } }")


@pytest.mark.parametrize("ipv6_enabled", [False, True])
def test_host_firewall_json_matches_every_expected_expression(
    ipv6_enabled: bool,
) -> None:
    payload = _host_firewall_json(ipv6_enabled=ipv6_enabled)

    verify_host_firewall_json(
        json.dumps(payload),
        ["eno1", "enp5s0"],
        ipv6_enabled=ipv6_enabled,
    )


@pytest.mark.parametrize(
    "expression",
    [
        [{"accept": None}],
        [
            _json_match({"meta": {"key": "nfproto"}}, "ipv4"),
            {"accept": None},
        ],
        [
            _json_match({"meta": {"key": "l4proto"}}, "sctp"),
            {"accept": None},
        ],
    ],
)
def test_host_firewall_json_rejects_broad_accept_with_unchanged_rule_count(
    expression: list[dict[str, object]],
) -> None:
    payload = _host_firewall_json(ipv6_enabled=False)
    rows = payload["nftables"]
    assert isinstance(rows, list)
    first_rule = next(row["rule"] for row in rows if isinstance(row, dict) and isinstance(row.get("rule"), dict))
    first_rule["expr"] = expression

    with pytest.raises(UmzugError, match="expressions or rule order"):
        verify_host_firewall_json(
            json.dumps(payload),
            ["eno1", "enp5s0"],
            ipv6_enabled=False,
        )


def test_host_firewall_json_rejects_an_additional_rule() -> None:
    payload = _host_firewall_json(ipv6_enabled=False)
    rows = payload["nftables"]
    assert isinstance(rows, list)
    rows.append(
        _json_rule(
            "umzug_host",
            "input",
            [
                _json_match({"meta": {"key": "iifname"}}, "lo"),
                {"accept": None},
            ],
        )
    )

    with pytest.raises(UmzugError, match="expressions or rule order"):
        verify_host_firewall_json(
            json.dumps(payload),
            ["eno1", "enp5s0"],
            ipv6_enabled=False,
        )


def test_host_firewall_json_rejects_reordered_rules() -> None:
    payload = _host_firewall_json(ipv6_enabled=False)
    rows = payload["nftables"]
    assert isinstance(rows, list)
    rule_indexes = [index for index, row in enumerate(rows) if isinstance(row, dict) and "rule" in row]
    rows[rule_indexes[0]], rows[rule_indexes[1]] = (
        rows[rule_indexes[1]],
        rows[rule_indexes[0]],
    )

    with pytest.raises(UmzugError, match="expressions or rule order"):
        verify_host_firewall_json(
            json.dumps(payload),
            ["eno1", "enp5s0"],
            ipv6_enabled=False,
        )


def test_loopback_guard_json_accepts_only_the_exact_loopback_rule() -> None:
    payload = _loopback_guard_json()

    verify_loopback_guard_json(
        json.dumps(payload),
        table_name="umzug_offline_guard",
        priority=-400,
    )


@pytest.mark.parametrize(
    "expression",
    [
        [{"accept": None}],
        [
            _json_match({"meta": {"key": "oifname"}}, "eth0"),
            {"accept": None},
        ],
        [
            _json_match(
                {"meta": {"key": "oifname"}},
                {"set": ["lo", "eth0"]},
                operator="in",
            ),
            {"accept": None},
        ],
        [
            {"accept": None},
            _json_match({"meta": {"key": "oifname"}}, "lo"),
        ],
    ],
)
def test_loopback_guard_json_rejects_broad_or_reordered_accept(
    expression: list[dict[str, object]],
) -> None:
    payload = _loopback_guard_json()
    rows = payload["nftables"]
    assert isinstance(rows, list)
    rule = next(row["rule"] for row in rows if isinstance(row, dict) and isinstance(row.get("rule"), dict))
    rule["expr"] = expression

    with pytest.raises(UmzugError, match="exact loopback"):
        verify_loopback_guard_json(
            json.dumps(payload),
            table_name="umzug_offline_guard",
            priority=-400,
        )


def test_loopback_guard_json_rejects_any_additional_accept_rule() -> None:
    payload = _loopback_guard_json()
    rows = payload["nftables"]
    assert isinstance(rows, list)
    rows.append(
        _json_rule(
            "umzug_offline_guard",
            "output",
            [
                _json_match({"meta": {"key": "oifname"}}, "eth0"),
                {"accept": None},
            ],
        )
    )

    with pytest.raises(UmzugError, match="unexpected or missing objects"):
        verify_loopback_guard_json(
            json.dumps(payload),
            table_name="umzug_offline_guard",
            priority=-400,
        )


def test_mullvad_json_check_is_explicitly_structural_not_dns_proof() -> None:
    # the structurally valid fixture intentionally contains no DNS expression.
    # passing proves only the documented base-chain/default-block properties.
    verify_mullvad_firewall_json(json.dumps(_mullvad_json()))


def test_mullvad_json_rejects_direct_physical_dns_accept() -> None:
    payload = _mullvad_json()
    rows = payload["nftables"]
    assert isinstance(rows, list)
    rows.insert(
        -1,
        _json_rule(
            "mullvad",
            "output",
            [
                _json_match({"meta": {"key": "oifname"}}, "eth0"),
                _json_match({"meta": {"key": "l4proto"}}, "udp"),
                _json_match(
                    {"payload": {"protocol": "udp", "field": "dport"}},
                    53,
                ),
                {"accept": None},
            ],
        ),
    )

    with pytest.raises(UmzugError, match="directly accepts DNS"):
        verify_mullvad_firewall_json(
            json.dumps(payload),
            ethernet_interfaces=["eth0"],
        )


def test_mullvad_json_allows_exact_non_dns_relay_port_on_ethernet() -> None:
    payload = _mullvad_json()
    rows = payload["nftables"]
    assert isinstance(rows, list)
    rows.insert(
        -1,
        _json_rule(
            "mullvad",
            "output",
            [
                _json_match({"meta": {"key": "oifname"}}, "eth0"),
                _json_match({"meta": {"key": "l4proto"}}, "udp"),
                _json_match(
                    {"payload": {"protocol": "udp", "field": "dport"}},
                    51820,
                ),
                {"accept": None},
            ],
        ),
    )

    verify_mullvad_firewall_json(
        json.dumps(payload),
        ethernet_interfaces=["eth0"],
    )


def _dns_route_evidence(
    resolvectl_status: str,
    resolv_conf: str,
    *,
    resolver_device: str = "wg-mullvad",
) -> dict[str, object]:
    sources = parse_effective_dns_sources(resolvectl_status, resolv_conf)
    lookups: list[dict[str, object]] = []
    for address in sorted({str(source["address"]) for source in sources}):
        device = "lo" if address.startswith("127.") else resolver_device
        lookups.append(
            {
                "address": address,
                "family": 4,
                "uid": 0,
                "exit": 0,
                "stdout": json.dumps([{"dst": address, "dev": device}]),
            }
        )
    return {"available": True, "sources": sources, "lookups": lookups}


def test_effective_dns_routes_require_loopback_or_observed_wireguard() -> None:
    status = """Global
       Current DNS Server: 10.64.0.1
              DNS Servers: 10.64.0.1
Link 7 (wg-mullvad)
              DNS Servers: 10.64.0.1
"""
    resolv_conf = "nameserver 127.0.0.53\n"
    verify_effective_dns_routes(
        resolvectl_status=status,
        resolv_conf=resolv_conf,
        wireguard_interfaces="wg-mullvad\n",
        route_evidence=_dns_route_evidence(status, resolv_conf),
        ethernet_interfaces=["eth0"],
    )


def test_effective_dns_routes_reject_physical_resolver_route() -> None:
    status = "Global\n       Current DNS Server: 10.64.0.1\n"
    resolv_conf = "nameserver 127.0.0.53\n"
    with pytest.raises(UmzugError, match="bypasses WireGuard"):
        verify_effective_dns_routes(
            resolvectl_status=status,
            resolv_conf=resolv_conf,
            wireguard_interfaces="wg-mullvad\n",
            route_evidence=_dns_route_evidence(
                status,
                resolv_conf,
                resolver_device="eth0",
            ),
            ethernet_interfaces=["eth0"],
        )


def test_effective_dns_routes_reject_resolver_bound_to_physical_link() -> None:
    status = """Global
Link 2 (eth0)
       Current DNS Server: 192.0.2.53
"""
    resolv_conf = "nameserver 127.0.0.53\n"
    with pytest.raises(UmzugError, match="bound to physical Ethernet"):
        verify_effective_dns_routes(
            resolvectl_status=status,
            resolv_conf=resolv_conf,
            wireguard_interfaces="wg-mullvad\n",
            route_evidence=_dns_route_evidence(status, resolv_conf),
            ethernet_interfaces=["eth0"],
        )


def test_static_resolv_conf_without_resolvectl_routes_via_wireguard() -> None:
    resolv_conf = "nameserver 10.64.0.1\n"
    verify_effective_dns_routes(
        resolvectl_status=None,
        resolv_conf=resolv_conf,
        wireguard_interfaces="wg-mullvad\n",
        route_evidence=_dns_route_evidence("", resolv_conf),
        ethernet_interfaces=["eth0"],
    )


def test_static_loopback_stub_without_upstream_evidence_fails_closed() -> None:
    resolv_conf = "nameserver 127.0.0.53\n"
    with pytest.raises(UmzugError, match="only a loopback stub"):
        verify_effective_dns_routes(
            resolvectl_status=None,
            resolv_conf=resolv_conf,
            wireguard_interfaces="wg-mullvad\n",
            route_evidence=_dns_route_evidence("", resolv_conf),
            ethernet_interfaces=["eth0"],
        )


def test_mullvad_json_rejects_unconditional_accept_all_before_drop() -> None:
    payload = _mullvad_json()
    rows = payload["nftables"]
    assert isinstance(rows, list)
    final_drop_index = max(
        index for index, row in enumerate(rows) if isinstance(row, dict) and isinstance(row.get("rule"), dict)
    )
    rows.insert(
        final_drop_index,
        _json_rule(
            "mullvad",
            "output",
            [{"comment": "dns"}, {"accept": None}],
        ),
    )

    with pytest.raises(UmzugError, match="unconditional accept"):
        verify_mullvad_firewall_json(json.dumps(payload))


def test_mullvad_json_rejects_accept_policy_even_with_terminal_block() -> None:
    payload = _mullvad_json()
    rows = payload["nftables"]
    assert isinstance(rows, list)
    chain = next(row["chain"] for row in rows if isinstance(row, dict) and "chain" in row)
    assert isinstance(chain, dict)
    chain["policy"] = "accept"

    with pytest.raises(UmzugError, match="invalid priority or policy"):
        verify_mullvad_firewall_json(json.dumps(payload))


def test_mullvad_json_accepts_drop_policy_as_structural_fallback() -> None:
    payload = _mullvad_json()
    rows = payload["nftables"]
    assert isinstance(rows, list)
    rows.pop()

    verify_mullvad_firewall_json(json.dumps(payload))


@pytest.mark.parametrize("verdict", ["jump", "goto", "return", "queue", "vmap"])
def test_mullvad_json_rejects_indirect_or_userspace_verdicts(verdict: str) -> None:
    payload = _mullvad_json()
    rows = payload["nftables"]
    assert isinstance(rows, list)
    rules = [row["rule"] for row in rows if isinstance(row, dict) and "rule" in row]
    assert rules and isinstance(rules[0], dict)
    rules[0]["expr"] = [{verdict: {"target": "leak"}}]

    with pytest.raises(UmzugError, match="indirect or userspace-controlled"):
        verify_mullvad_firewall_json(json.dumps(payload))


def test_systemd_firewall_unit_uses_portable_search_path_and_recovery_is_persistent() -> None:
    unit = firewall_systemd_unit("/etc/umzug/firewall.nft")
    assert "ExecStart=nft -f /etc/umzug/firewall.nft" in unit
    assert "ExecStartPre" not in unit
    assert "ExecStop" not in unit
    assert "delete table" not in unit
    assert "/usr/sbin/nft" not in unit
    recovery = recovery_script()
    assert '"$SYSTEMCTL" disable --now "$unit"' in recovery
    assert "delete table inet $table" in recovery
    assert "disabled-by-recovery" in recovery


def test_wireguard_killswitch_allows_only_tunnel_literal_endpoint_and_dhcp() -> None:
    rules = manual_wireguard_killswitch_rules(
        ["enp5s0", "eno1"],
        tunnel_interface="wg-mullvad",
        endpoint_ip="193.32.249.66",
        endpoint_port=51820,
    )
    effective = _without_comments(rules)

    assert re.search(
        r"chain\s+output\s*\{\s*type filter hook output priority -100; policy drop;",
        effective,
    )
    assert _accept_rules(rules) == {
        'oifname "lo" accept',
        'oifname "wg-mullvad" accept',
        "oifname @ethernet_ifaces ip daddr 193.32.249.66 udp dport 51820 accept",
        ("oifname @ethernet_ifaces ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept"),
    }
    assert "ct state established" not in effective
    assert "ct state related" not in effective
    assert "udp dport 53" not in effective
    assert "tcp dport 53" not in effective
    assert "0.0.0.0/0" not in effective
    assert_no_ssh_exposure(rules)


def test_wireguard_ipv6_endpoint_has_no_ipv4_dhcp_or_implicit_lan_exception() -> None:
    rules = manual_wireguard_killswitch_rules(
        ["eth0"],
        tunnel_interface="wg0",
        endpoint_ip="2001:db8::5",
        endpoint_port=51820,
    )

    assert _accept_rules(rules) == {
        'oifname "lo" accept',
        'oifname "wg0" accept',
        "oifname @ethernet_ifaces ip6 daddr 2001:db8::5 udp dport 51820 accept",
    }
    assert "udp sport 68" not in rules
    assert "10.0.0.0/8" not in rules
    assert "172.16.0.0/12" not in rules
    assert "192.168.0.0/16" not in rules


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"endpoint_ip": "relay.example.invalid"}, "literal IP"),
        ({"endpoint_ip": "193.32.249.66; accept"}, "literal IP"),
        ({"endpoint_port": 0}, "invalid WireGuard endpoint"),
        ({"endpoint_port": 65536}, "invalid WireGuard endpoint"),
        ({"endpoint_protocol": "tcp"}, "invalid WireGuard endpoint"),
        ({"endpoint_protocol": "any"}, "invalid WireGuard endpoint"),
        ({"tunnel_interface": 'wg0" accept'}, "invalid tunnel interface"),
    ],
)
def test_wireguard_killswitch_rejects_nonliteral_or_injectable_parameters(
    overrides: dict[str, object],
    message: str,
) -> None:
    parameters: dict[str, object] = {
        "tunnel_interface": "wg0",
        "endpoint_ip": "193.32.249.66",
        "endpoint_port": 51820,
        "endpoint_protocol": "udp",
    }
    parameters.update(overrides)

    with pytest.raises(UmzugError, match=message):
        manual_wireguard_killswitch_rules(["eth0"], **parameters)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "interfaces",
    [[], ["eth0; accept"], ['eth0"'], ["x" * 16], ["eth0\neth1"]],
)
def test_physical_interface_names_are_validated_before_nft_rendering(
    interfaces: list[str],
) -> None:
    with pytest.raises(UmzugError):
        validate_interfaces(interfaces)


def test_source_mount_parser_unescapes_and_selects_deepest_mount(tmp_path: Path) -> None:
    medium = tmp_path / "USB Drive"
    nested = medium / "nested"
    nested.mkdir(parents=True)
    target = nested / "bundle.tar"
    target.touch()
    escaped_medium = str(medium).replace(" ", r"\040")
    escaped_nested = str(nested).replace(" ", r"\040")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "\n".join(
            [
                "20 1 0:1 / / rw,relatime - ext4 /dev/root rw",
                (
                    f"30 20 8:1 / {escaped_medium} "
                    "ro,nosuid,nodev,noexec,relatime shared:4 "
                    "- ext4 /dev/disk\\040by-id/usb ro"
                ),
                (f"31 30 8:2 / {escaped_nested} ro,nosuid - ext4 /dev/mapper/unsafe ro"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = inspect_mount(target, mountinfo)

    assert result.mountpoint == str(nested)
    assert result.filesystem == "ext4"
    assert result.source == "/dev/mapper/unsafe"
    assert set(result.options) == {"ro", "nosuid"}
    assert set(result.missing) == {"nodev", "noexec"}
    assert not result.safe

    parent_result = inspect_mount(medium, mountinfo)
    assert parent_result.mountpoint == str(medium)
    assert parent_result.source == "/dev/disk by-id/usb"
    assert REQUIRED_OPTIONS <= set(parent_result.options)
    assert parent_result.missing == ()
    assert parent_result.safe


def test_source_mount_parser_does_not_confuse_path_prefixes(tmp_path: Path) -> None:
    medium = tmp_path / "media"
    similarly_named = tmp_path / "media-other"
    medium.mkdir()
    similarly_named.mkdir()
    mountinfo = tmp_path / "mountinfo-prefix"
    mountinfo.write_text(
        "\n".join(
            [
                "20 1 0:1 / / ro,nosuid,nodev,noexec - ext4 /dev/root ro",
                (f"30 20 8:1 / {medium} rw,nosuid,nodev,noexec - ext4 /dev/sdb1 rw"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = inspect_mount(similarly_named, mountinfo)

    assert result.mountpoint == "/"
    assert result.safe
