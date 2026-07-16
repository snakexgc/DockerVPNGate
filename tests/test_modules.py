from __future__ import annotations

import copy
import base64
import io
import json
import socket
import threading
import time
import subprocess
import tempfile
import urllib.error
import urllib.request
import unittest
from pathlib import Path
from http.server import HTTPServer
from types import SimpleNamespace
from unittest.mock import patch

from vpngate_app.config import (
    DEFAULT_MAX_SCAN_ROWS, DEFAULT_NODE_AUTO_RETEST_SECONDS_PER_NODE,
    DEFAULT_NODE_TEST_WORKERS, PROXY_INTERFACES, PROXY_PORTS,
)
from vpngate_app import logging_utils, node_testing, storage, vpngate_source
from vpngate_app import openvpn_runtime, policy_routing
from vpngate_app.logging_io import Tee
from vpngate_app.openvpn_config import UnsafeOpenVPNConfig, validate_openvpn_config
from vpngate_app.node_testing import (
    NODE_STATUS_AVAILABLE, NODE_STATUS_QUEUED, NODE_STATUS_TESTING,
    NODE_STATUS_UNAVAILABLE, sort_all_nodes,
)
from vpngate_app.storage import normalize_proxy_slots
from vpngate_app.traffic import TrafficMonitor
from vpngate_app.web_api import bounded_int_setting, create_handler, is_routine_successful_poll
import vpngate_manager
import proxy_server


class ConfigTests(unittest.TestCase):
    def test_fixed_proxy_layout(self) -> None:
        self.assertEqual(PROXY_PORTS, (7928, 7929, 7930, 7931, 7932))
        self.assertEqual(PROXY_INTERFACES, ("tun0", "tun1", "tun2", "tun3", "tun4"))

    def test_slot_normalization_rejects_unknown_modes(self) -> None:
        slots = normalize_proxy_slots([{"routing_ip_type": "unknown", "switch_mode": "unknown"}])
        self.assertEqual(len(slots), 5)
        self.assertEqual(slots[0]["routing_ip_type"], "all")
        self.assertEqual(slots[0]["switch_mode"], "auto")

    def test_web_performance_defaults_match_runtime_defaults(self) -> None:
        self.assertEqual(DEFAULT_NODE_TEST_WORKERS, 8)
        self.assertEqual(DEFAULT_MAX_SCAN_ROWS, 300)
        self.assertEqual(DEFAULT_NODE_AUTO_RETEST_SECONDS_PER_NODE, 10)

    def test_web_performance_settings_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(storage, "DATA_DIR", Path(temp_dir)):
            config = storage.load_ui_config()
            self.assertEqual(config["node_test_workers"], 8)
            self.assertEqual(config["max_scan_rows"], 300)
            self.assertEqual(config["node_auto_retest_seconds_per_node"], 10)
            self.assertNotIn("api_url", config)
            self.assertNotIn("api_ssl_verify", config)

            config.update(
                node_test_workers=2,
                max_scan_rows=150,
                node_auto_retest_seconds_per_node=30,
            )
            storage.save_ui_config(config)
            reloaded = storage.load_ui_config()

        self.assertEqual(reloaded["node_test_workers"], 2)
        self.assertEqual(reloaded["max_scan_rows"], 150)
        self.assertEqual(reloaded["node_auto_retest_seconds_per_node"], 30)


class TrafficTests(unittest.TestCase):
    def test_reset_uses_current_counters_as_new_baseline(self) -> None:
        monitor = TrafficMonitor(("tun-test",))
        counters = {"rx_bytes": 10_000, "tx_bytes": 5_000}
        monitor.read_counter = lambda _interface, counter: counters[counter]  # type: ignore[method-assign]
        monitor.sample_slot(0)
        counters.update(rx_bytes=12_000, tx_bytes=6_000)
        monitor.slots[0]["last_sample"] = time.monotonic() - 1
        monitor.sample_slot(0)
        self.assertEqual(monitor.slot_payload(0)["total"], 3_000)

        reset = monitor.reset()
        self.assertEqual(reset["slots"][0]["total"], 0)
        counters.update(rx_bytes=12_600, tx_bytes=6_300)
        monitor.slots[0]["last_sample"] = time.monotonic() - 1
        monitor.sample_slot(0)
        self.assertEqual(monitor.slot_payload(0)["total"], 900)


class NodeStatusTests(unittest.TestCase):
    def test_latency_target_resolution_uses_the_same_doh_priority(self) -> None:
        old_cache = dict(node_testing.latency_dns_cache)

        def doh_result(_host, _qtype, endpoint, _bootstrap_ip, _timeout, interface):
            self.assertIsNone(interface)
            if endpoint == "https://dns.alidns.com/dns-query":
                return "203.0.113.40"
            return None

        try:
            node_testing.latency_dns_cache.update(ips=[], expires_at=0.0)
            with patch.object(
                proxy_server,
                "doh_query_over_interface",
                side_effect=doh_result,
            ) as mocked_doh:
                resolved = node_testing.resolve_latency_test_ips()

            self.assertEqual(resolved, ["203.0.113.40"])
            self.assertEqual(
                [item.args[2] for item in mocked_doh.call_args_list],
                [
                    "https://dns.cloudflare.com/dns-query",
                    "https://dns.google/dns-query",
                    "https://dns.alidns.com/dns-query",
                ],
            )
        finally:
            node_testing.latency_dns_cache.clear()
            node_testing.latency_dns_cache.update(old_cache)

    def test_queued_nodes_are_kept_in_pending_group(self) -> None:
        nodes = [
            {"id": "slow", "probe_status": "unavailable", "score": 999, "probed_at": 10},
            {"id": "pending", "probe_status": NODE_STATUS_QUEUED, "score": 100, "ping": 10},
            {"id": "fast", "probe_status": "available", "latency_ms": 50, "score": 1},
        ]
        self.assertEqual([node["id"] for node in sort_all_nodes(nodes)], ["fast", "pending", "slow"])

    def test_google_204_probe_uses_five_second_timeout(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(command, capture_output, text, timeout):
            captured["command"] = command
            captured["timeout"] = timeout
            return subprocess.CompletedProcess(command, 0, stdout="0.123 204", stderr="")

        with (
            patch.object(node_testing, "resolve_latency_test_ips", return_value=["142.250.72.36"]),
            patch.object(node_testing.subprocess, "run", side_effect=fake_run),
        ):
            ok, latency, _message = node_testing.measure_tunnel_http_latency("tun-test")

        command = captured["command"]
        self.assertTrue(ok)
        self.assertEqual(latency, 123)
        self.assertIsInstance(command, list)
        self.assertEqual(command[command.index("--connect-timeout") + 1], "5")
        self.assertEqual(command[command.index("--max-time") + 1], "5")
        self.assertEqual(captured["timeout"], 7)


class DashboardPayloadTests(unittest.TestCase):
    def test_requested_country_names_and_iso_codes_are_translated(self) -> None:
        translations = {
            "Northern Mariana Islands": ("MP", "北马里亚纳群岛"),
            "Belarus": ("BY", "白俄罗斯"),
            "Ecuador": ("EC", "厄瓜多尔"),
            "Lao People's Democratic Republic": ("LA", "老挝"),
            "Lithuania": ("LT", "立陶宛"),
            "Peru": ("PE", "秘鲁"),
            "Myanmar": ("MM", "缅甸"),
        }

        for english_name, (country_code, chinese_name) in translations.items():
            with self.subTest(country=english_name):
                self.assertEqual(vpngate_manager.normalized_country_name(english_name), chinese_name)
                self.assertEqual(vpngate_manager.normalized_country_name(country_code), chinese_name)

    def test_country_choices_include_counts_and_merge_translated_aliases(self) -> None:
        canada = vpngate_manager.normalized_country_name("Canada")
        choices = vpngate_manager.country_choice_payloads([
            {"country": "Canada"},
            {"country": canada},
            {"country": "Japan"},
            {"country": ""},
            {},
        ])

        by_value = {choice["value"]: choice for choice in choices}
        self.assertEqual(by_value[canada]["count"], 2)
        self.assertEqual(sum(choice["count"] for choice in choices), 3)
        if canada != "Canada":
            self.assertEqual(by_value[canada]["aliases"], ["Canada"])

    def test_country_choices_keep_known_alias_for_legacy_preference(self) -> None:
        canada = vpngate_manager.normalized_country_name("Canada")
        if canada == "Canada":
            self.skipTest("Canada has no translated alias in this configuration")

        choices = vpngate_manager.country_choice_payloads([{"country": canada}])

        self.assertIn("Canada", choices[0]["aliases"])


class RegionNodePoolTests(unittest.TestCase):
    @staticmethod
    def node(
        node_id: str,
        country: str,
        status: str,
        latency: int = 0,
        origin: str = "existing",
        ip_type: str = "hosting",
    ) -> dict[str, object]:
        return {
            "id": node_id,
            "country": country,
            "probe_status": status,
            "latency_ms": latency,
            "latency_source": vpngate_manager.LATENCY_SOURCE,
            "score": 100,
            "_pool_origin": origin,
            "ip_type": ip_type,
        }

    def test_limit_is_applied_independently_per_region(self) -> None:
        nodes = [
            self.node("jp1", "Japan", NODE_STATUS_AVAILABLE, 20),
            self.node("jp2", "Japan", NODE_STATUS_AVAILABLE, 30),
            self.node("jp3", "Japan", NODE_STATUS_AVAILABLE, 40),
            self.node("kr1", "Korea Republic of", NODE_STATUS_AVAILABLE, 25),
            self.node("kr2", "Korea Republic of", NODE_STATUS_AVAILABLE, 35),
        ]
        selected, stats = vpngate_manager.merge_node_cache([], nodes, 2)
        counts: dict[str, int] = {}
        for node in selected:
            country = vpngate_manager.normalized_country_name(node["country"])
            counts[country] = counts.get(country, 0) + 1
        self.assertEqual(sorted(counts.values()), [2, 2])
        self.assertEqual(stats["region_limit"], 2)

    def test_valid_new_nodes_replace_timeout_then_slow_old_nodes(self) -> None:
        nodes = [
            self.node("old-timeout", "Japan", NODE_STATUS_UNAVAILABLE),
            self.node("old-fast", "Japan", NODE_STATUS_AVAILABLE, 30),
            self.node("old-slow", "Japan", NODE_STATUS_AVAILABLE, 300),
            self.node("new-fast", "Japan", NODE_STATUS_AVAILABLE, 40, "new"),
        ]
        selected, _stats = vpngate_manager.merge_node_cache([], nodes, 2)
        self.assertEqual({node["id"] for node in selected}, {"old-fast", "new-fast"})

    def test_valid_new_node_replaces_slowest_old_even_when_new_is_slower(self) -> None:
        nodes = [
            self.node("old-fast", "Japan", NODE_STATUS_AVAILABLE, 20),
            self.node("old-slow", "Japan", NODE_STATUS_AVAILABLE, 200),
            self.node("new-valid", "Japan", NODE_STATUS_AVAILABLE, 500, "new"),
        ]
        selected, _stats = vpngate_manager.merge_node_cache([], nodes, 2)
        self.assertEqual({node["id"] for node in selected}, {"old-fast", "new-valid"})

    def test_region_limit_reserves_half_for_residential_or_mobile_nodes(self) -> None:
        nodes = [
            self.node("hosting-fast", "Japan", NODE_STATUS_AVAILABLE, 10),
            self.node("hosting-medium", "Japan", NODE_STATUS_AVAILABLE, 20),
            self.node("hosting-slow", "Japan", NODE_STATUS_AVAILABLE, 30),
            self.node("residential", "Japan", NODE_STATUS_AVAILABLE, 400, ip_type="residential"),
            self.node("mobile", "Japan", NODE_STATUS_AVAILABLE, 500, ip_type="mobile"),
        ]
        selected, _stats = vpngate_manager.merge_node_cache([], nodes, 4)
        self.assertEqual(
            {node["id"] for node in selected},
            {"hosting-fast", "hosting-medium", "residential", "mobile"},
        )

    def test_odd_region_limit_rounds_residential_reservation_up(self) -> None:
        nodes = [
            self.node("hosting-1", "Japan", NODE_STATUS_AVAILABLE, 10),
            self.node("hosting-2", "Japan", NODE_STATUS_AVAILABLE, 20),
            self.node("hosting-3", "Japan", NODE_STATUS_AVAILABLE, 30),
            self.node("residential-1", "Japan", NODE_STATUS_AVAILABLE, 300, ip_type="residential"),
            self.node("residential-2", "Japan", NODE_STATUS_AVAILABLE, 400, ip_type="residential"),
            self.node("mobile", "Japan", NODE_STATUS_AVAILABLE, 500, ip_type="mobile"),
        ]
        selected, _stats = vpngate_manager.merge_node_cache([], nodes, 5)
        selected_residential = [
            node for node in selected if node["ip_type"] in ("residential", "mobile")
        ]
        self.assertEqual(len(selected_residential), 3)

    def test_residential_shortage_keeps_available_hosting_nodes(self) -> None:
        nodes = [
            self.node("residential", "Japan", NODE_STATUS_AVAILABLE, 300, ip_type="residential"),
            self.node("hosting-1", "Japan", NODE_STATUS_AVAILABLE, 10),
            self.node("hosting-2", "Japan", NODE_STATUS_AVAILABLE, 20),
            self.node("hosting-3", "Japan", NODE_STATUS_AVAILABLE, 30),
            self.node("residential-down", "Japan", NODE_STATUS_UNAVAILABLE, ip_type="residential"),
        ]
        selected, _stats = vpngate_manager.merge_node_cache([], nodes, 4)
        self.assertEqual(
            {node["id"] for node in selected},
            {"residential", "hosting-1", "hosting-2", "hosting-3"},
        )

    def test_residential_above_half_competes_by_latency(self) -> None:
        nodes = [
            self.node("residential-fast", "Japan", NODE_STATUS_AVAILABLE, 10, ip_type="residential"),
            self.node("mobile-fast", "Japan", NODE_STATUS_AVAILABLE, 20, ip_type="mobile"),
            self.node("residential-slow", "Japan", NODE_STATUS_AVAILABLE, 500, ip_type="residential"),
            self.node("hosting-1", "Japan", NODE_STATUS_AVAILABLE, 30),
            self.node("hosting-2", "Japan", NODE_STATUS_AVAILABLE, 40),
        ]
        selected, _stats = vpngate_manager.merge_node_cache([], nodes, 4)
        self.assertEqual(
            {node["id"] for node in selected},
            {"residential-fast", "mobile-fast", "hosting-1", "hosting-2"},
        )

    def test_all_timeout_region_rotates_to_new_nodes_without_shrinking(self) -> None:
        nodes = [
            self.node("old1", "Canada", NODE_STATUS_UNAVAILABLE),
            self.node("old2", "Canada", NODE_STATUS_UNAVAILABLE),
            self.node("new1", "Canada", NODE_STATUS_UNAVAILABLE, origin="new"),
            self.node("new2", "Canada", NODE_STATUS_UNAVAILABLE, origin="new"),
        ]
        selected, _stats = vpngate_manager.merge_node_cache([], nodes, 2)
        self.assertEqual({node["id"] for node in selected}, {"new1", "new2"})

    def test_active_node_is_protected_from_region_trim(self) -> None:
        nodes = [
            self.node("active", "Japan", NODE_STATUS_UNAVAILABLE),
            self.node("new", "Japan", NODE_STATUS_AVAILABLE, 10, "new"),
        ]
        selected, _stats = vpngate_manager.merge_node_cache([], nodes, 1, {"active"})
        self.assertEqual([node["id"] for node in selected], ["active"])

    def test_fetch_failure_keeps_local_pool_and_completes_startup_test(self) -> None:
        existing = [self.node("old", "Canada", NODE_STATUS_AVAILABLE, 30)]
        old_done = vpngate_manager.initial_node_pool_test_done
        try:
            vpngate_manager.initial_node_pool_test_done = False
            with (
                patch.object(vpngate_manager, "read_nodes", return_value=existing),
                patch.object(
                    vpngate_manager,
                    "fetch_candidates",
                    side_effect=RuntimeError("offline"),
                ) as fetch_nodes,
                patch.object(vpngate_manager, "load_ui_config", return_value={
                    "region_node_limit": 2,
                    "node_test_workers": 2,
                    "max_scan_rows": 150,
                    "node_auto_retest_seconds_per_node": 30,
                    "proxy_slots": [{} for _ in PROXY_PORTS],
                }),
                patch.object(vpngate_manager, "test_multiple_nodes") as test_nodes,
                patch.object(vpngate_manager, "ensure_proxy_slot"),
                patch.object(vpngate_manager, "pending_probe_count_from_nodes", return_value=0),
                patch.object(vpngate_manager, "set_state"),
                patch.object(vpngate_manager, "log_to_json"),
            ):
                message = vpngate_manager.multi_maintain_nodes(force=True, wait=True)
            test_nodes.assert_called_once_with(["old"], 2)
            fetch_nodes.assert_called_once_with(150)
            self.assertIn("本地池已保留", message)
            self.assertTrue(vpngate_manager.initial_node_pool_test_done)
        finally:
            vpngate_manager.initial_node_pool_test_done = old_done

    def test_staged_refresh_failure_restores_previous_snapshot(self) -> None:
        existing = [self.node("old", "Canada", NODE_STATUS_AVAILABLE, 30)]
        fetched = [self.node("new", "Canada", NODE_STATUS_QUEUED, origin="new")]
        writes: list[tuple[Path, object]] = []
        with (
            patch.object(vpngate_manager, "read_nodes", return_value=existing),
            patch.object(vpngate_manager, "fetch_candidates", return_value=fetched),
            patch.object(vpngate_manager, "load_ui_config", return_value={"region_node_limit": 2, "proxy_slots": [{} for _ in PROXY_PORTS]}),
            patch.object(vpngate_manager, "test_multiple_nodes", side_effect=RuntimeError("probe crashed")),
            patch.object(vpngate_manager, "set_state"),
            patch.object(vpngate_manager, "write_json", side_effect=lambda path, data: writes.append((path, data))),
        ):
            with self.assertRaisesRegex(RuntimeError, "probe crashed"):
                vpngate_manager.multi_maintain_nodes(force=True, wait=True)
        node_writes = [data for path, data in writes if path == vpngate_manager.NODES_FILE]
        self.assertGreaterEqual(len(node_writes), 2)
        self.assertEqual(node_writes[-1], existing)


class NetworkIsolationTests(unittest.TestCase):
    def test_managed_openvpn_cannot_modify_container_routes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "node.ovpn"
            config_path.write_text(
                "client\nproto udp\nremote 192.0.2.10 1194\nredirect-gateway def1\n",
                encoding="utf-8",
            )
            with patch.object(openvpn_runtime, "get_openvpn_version", return_value=2.6):
                command = openvpn_runtime.openvpn_command(str(config_path), True, "tun10")

        self.assertIn("--route-nopull", command)
        self.assertIn("--route-noexec", command)
        self.assertEqual(command[command.index("--script-security") + 1], "1")

    def test_unisolated_openvpn_command_does_not_force_route_noexec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "node.ovpn"
            config_path.write_text("client\nproto udp\nremote 192.0.2.10 1194\n", encoding="utf-8")
            with patch.object(openvpn_runtime, "get_openvpn_version", return_value=2.6):
                command = openvpn_runtime.openvpn_command(str(config_path), False, "tun10")

        self.assertNotIn("--route-nopull", command)
        self.assertNotIn("--route-noexec", command)

    def test_policy_rule_has_stable_cleanup_priority(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(
                command,
                1 if command[:3] == ["ip", "rule", "del"] else 0,
                stdout="",
                stderr="",
            )

        with patch.object(policy_routing.subprocess, "run", side_effect=fake_run):
            policy_routing.setup_policy_routing("tun10", 1010, 21010)
            policy_routing.cleanup_policy_routing("tun10", 1010, 21010)

        self.assertIn(
            ["ip", "rule", "add", "priority", "21010", "oif", "tun10", "table", "1010"],
            commands,
        )
        self.assertIn(["ip", "rule", "del", "priority", "21010"], commands)


class RemoteProfileSecurityTests(unittest.TestCase):
    VALID_PROFILE = (
        "client\n"
        "dev tun\n"
        "proto udp\n"
        "remote 192.0.2.10 1194\n"
        "cipher AES-128-CBC\n"
        "auth SHA1\n"
        "resolv-retry infinite\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
        "remote-cert-tls server\n"
        "<ca>\ncertificate-data\n</ca>\n"
    )

    def test_downloaded_profile_allowlist_accepts_connection_and_tls_material(self) -> None:
        validate_openvpn_config(self.VALID_PROFILE)
        encoded = base64.b64encode(self.VALID_PROFILE.encode("utf-8")).decode("ascii")
        self.assertEqual(vpngate_source.decode_config(encoded), self.VALID_PROFILE)

    def test_downloaded_profile_rejects_scripts_plugins_and_included_files(self) -> None:
        for directive in ("script-security 2", "up /tmp/payload", "plugin payload.so", "config nested.conf"):
            with self.subTest(directive=directive):
                with self.assertRaises(UnsafeOpenVPNConfig):
                    validate_openvpn_config(self.VALID_PROFILE + directive + "\n")

    def test_runtime_revalidates_profile_before_starting_openvpn(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "unsafe.ovpn"
            config_path.write_text(
                "client\nremote 192.0.2.10 1194\nscript-security 2\nup /tmp/payload\n",
                encoding="utf-8",
            )
            with patch.object(openvpn_runtime.subprocess, "Popen") as mocked_popen:
                ok, message, process = openvpn_runtime.run_openvpn_until_ready(
                    str(config_path), keep_alive=False, route_nopull=True,
                )

        self.assertFalse(ok)
        self.assertIsNone(process)
        self.assertIn("ERR_OVPN_UNSAFE_CONFIG", message)
        mocked_popen.assert_not_called()

    def test_api_fetch_uses_fixed_https_without_custom_ssl_options(self) -> None:
        calls: list[str] = []
        api_url = vpngate_source.API_URL

        def fail_fetch(url: str) -> str:
            calls.append(url)
            raise RuntimeError("offline")

        with (
            patch.object(vpngate_source, "cached_nodes", return_value=[]),
            patch.object(vpngate_source, "load_blacklist", return_value={}),
            patch.object(vpngate_source, "fetch_api_text", side_effect=fail_fetch),
            patch.object(vpngate_source.time, "sleep"),
            patch.object(vpngate_source.vpn_utils, "diagnose_api_failure", return_value=(1001, "offline")),
            patch.object(vpngate_source, "_set_state"),
            patch.object(vpngate_source, "log_to_json"),
        ):
            with self.assertRaisesRegex(RuntimeError, "offline"):
                vpngate_source.fetch_candidates()

        self.assertEqual(api_url, "https://www.vpngate.net/api/iphone/")
        self.assertEqual(calls, [api_url] * 2)

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                pass

            def read(self) -> bytes:
                return b"api-response"

        with (
            patch.object(vpngate_source.vpn_utils, "get_upstream_proxy", return_value=(None, None, None)),
            patch.object(vpngate_source.urllib.request, "urlopen", return_value=FakeResponse()) as mocked_urlopen,
        ):
            self.assertEqual(
                vpngate_source.fetch_api_text(api_url),
                "api-response",
            )

        self.assertNotIn("context", mocked_urlopen.call_args.kwargs)
        with self.assertRaisesRegex(ValueError, "HTTP 或 HTTPS URL"):
            vpngate_source.fetch_api_text("ftp://reverse-proxy.example.test/vpngate")


class ProxySafetyTests(unittest.TestCase):
    def test_dns_resolution_uses_foreign_doh_before_domestic_doh(self) -> None:
        host = "foreign-first.example.test"

        def doh_result(_host, qtype, endpoint, _bootstrap_ip, _timeout, _interface):
            if endpoint == "https://dns.alidns.com/dns-query" and qtype == 1:
                return "203.0.113.10"
            return None

        with (
            patch.object(proxy_server, "doh_query_over_interface", side_effect=doh_result) as mocked_doh,
            patch.object(proxy_server, "dns_query_over_interface") as mocked_plain_dns,
        ):
            resolved = proxy_server.resolve_dns_over_interface(host, "tun0")

        self.assertEqual(resolved, "203.0.113.10")
        self.assertEqual(
            [(item.args[2], item.args[1]) for item in mocked_doh.call_args_list],
            [
                ("https://dns.cloudflare.com/dns-query", 1),
                ("https://dns.cloudflare.com/dns-query", 28),
                ("https://dns.google/dns-query", 1),
                ("https://dns.google/dns-query", 28),
                ("https://dns.alidns.com/dns-query", 1),
            ],
        )
        mocked_plain_dns.assert_not_called()

    def test_dns_resolution_falls_back_to_plain_dns_after_all_doh(self) -> None:
        host = "plain-fallback.example.test"

        def plain_dns_result(_host, qtype, dns_server, _timeout, _interface):
            if dns_server == "223.5.5.5" and qtype == 1:
                return "203.0.113.20"
            return None

        with (
            patch.object(proxy_server, "doh_query_over_interface", return_value=None) as mocked_doh,
            patch.object(proxy_server, "dns_query_over_interface", side_effect=plain_dns_result) as mocked_plain_dns,
        ):
            resolved = proxy_server.resolve_dns_over_interface(host, "tun1")

        self.assertEqual(resolved, "203.0.113.20")
        self.assertEqual(len(mocked_doh.call_args_list), 6)
        self.assertEqual(
            [(item.args[2], item.args[1]) for item in mocked_plain_dns.call_args_list],
            [
                ("1.1.1.1", 1),
                ("1.1.1.1", 28),
                ("8.8.8.8", 1),
                ("8.8.8.8", 28),
                ("223.5.5.5", 1),
            ],
        )

    def test_dns_cache_is_isolated_by_tunnel_interface(self) -> None:
        host = "cache.example.test"
        with (
            patch.object(proxy_server, "doh_query_over_interface", return_value="203.0.113.30") as mocked_doh,
            patch.object(proxy_server, "dns_query_over_interface") as mocked_plain_dns,
        ):
            first = proxy_server.resolve_dns_over_interface(host, "tun2")
            cached = proxy_server.resolve_dns_over_interface(host, "tun2")
            other_tunnel = proxy_server.resolve_dns_over_interface(host, "tun3")

        self.assertEqual((first, cached, other_tunnel), ("203.0.113.30",) * 3)
        self.assertEqual(mocked_doh.call_count, 2)
        mocked_plain_dns.assert_not_called()

    def test_dns_failure_does_not_fall_back_to_physical_system_resolver(self) -> None:
        with (
            patch.object(proxy_server, "resolve_dns_over_interface", return_value=None),
            patch.object(proxy_server.socket, "getaddrinfo") as mocked_getaddrinfo,
            patch.object(proxy_server.socket, "socket") as mocked_socket,
        ):
            with self.assertRaisesRegex(OSError, "ERR_TUN_DNS_FAILED"):
                proxy_server.create_connection(("example.com", 443), "tun0")

        mocked_getaddrinfo.assert_not_called()
        mocked_socket.assert_not_called()

    def test_accept_threads_keep_their_own_client_and_address(self) -> None:
        class FakeClient:
            def __init__(self, name: str):
                self.name = name
                self.closed = False

            def close(self) -> None:
                self.closed = True

        clients = [FakeClient("first"), FakeClient("second")]

        class FakeServer:
            def __init__(self):
                self.accept_index = 0

            def setsockopt(self, *_args) -> None:
                pass

            def bind(self, *_args) -> None:
                pass

            def listen(self, *_args) -> None:
                pass

            def accept(self):
                if self.accept_index >= len(clients):
                    raise KeyboardInterrupt
                index = self.accept_index
                self.accept_index += 1
                return clients[index], (f"192.0.2.{index + 1}", 10000 + index)

        targets: list[object] = []

        class DeferredThread:
            def __init__(self, target, daemon=False):
                self.target = target
                targets.append(target)

            def start(self) -> None:
                pass

        with (
            patch.object(proxy_server.socket, "socket", return_value=FakeServer()),
            patch.object(proxy_server.threading, "Thread", DeferredThread),
            patch.object(proxy_server, "proxy_connection_sem", threading.BoundedSemaphore(2)),
            patch.object(proxy_server, "proxy_client") as mocked_proxy_client,
        ):
            with self.assertRaises(KeyboardInterrupt):
                proxy_server.start_proxy_server("127.0.0.1", 7928, "tun0")
            for target in targets:
                target()

        self.assertEqual(mocked_proxy_client.call_count, 2)
        self.assertIs(mocked_proxy_client.call_args_list[0].args[0], clients[0])
        self.assertEqual(mocked_proxy_client.call_args_list[0].args[1], ("192.0.2.1", 10000))
        self.assertIs(mocked_proxy_client.call_args_list[1].args[0], clients[1])
        self.assertEqual(mocked_proxy_client.call_args_list[1].args[1], ("192.0.2.2", 10001))


class ConcurrentStateTests(unittest.TestCase):
    def test_ui_config_transactions_preserve_independent_concurrent_updates(self) -> None:
        errors: list[BaseException] = []
        start = threading.Barrier(2)

        def worker(mutator) -> None:
            try:
                start.wait(timeout=2)
                storage.update_ui_config(mutator)
            except BaseException as exc:
                errors.append(exc)

        def update_first(config: dict[str, object]) -> None:
            time.sleep(0.03)
            config["proxy_slots"][0]["preferred_country"] = "Japan"  # type: ignore[index]

        def update_second(config: dict[str, object]) -> None:
            config["proxy_slots"][1]["enabled"] = False  # type: ignore[index]

        with tempfile.TemporaryDirectory() as temp_dir, patch.object(storage, "DATA_DIR", Path(temp_dir)):
            threads = [
                threading.Thread(target=worker, args=(update_first,)),
                threading.Thread(target=worker, args=(update_second,)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)
            config = storage.load_ui_config()

        self.assertFalse(errors)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(config["proxy_slots"][0]["preferred_country"], "Japan")
        self.assertFalse(config["proxy_slots"][1]["enabled"])

    def test_node_mutations_reread_latest_snapshot_before_each_write(self) -> None:
        current = [
            {"id": "first", "probe_status": NODE_STATUS_QUEUED, "latency_ms": 0},
            {"id": "second", "probe_status": NODE_STATUS_QUEUED, "latency_ms": 0},
        ]

        def fake_read_nodes() -> list[dict[str, object]]:
            return copy.deepcopy(current)

        def fake_write_json(_path: Path, data: list[dict[str, object]]) -> None:
            current[:] = copy.deepcopy(data)

        def update_first(node: dict[str, object]) -> None:
            time.sleep(0.03)
            node["latency_ms"] = 25

        def update_second(node: dict[str, object]) -> None:
            node["probe_status"] = NODE_STATUS_AVAILABLE

        with (
            patch.object(vpngate_manager, "read_nodes", side_effect=fake_read_nodes),
            patch.object(vpngate_manager, "write_json", side_effect=fake_write_json),
        ):
            threads = [
                threading.Thread(target=vpngate_manager.mutate_cached_node, args=("first", update_first)),
                threading.Thread(target=vpngate_manager.mutate_cached_node, args=("second", update_second)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)

        by_id = {node["id"]: node for node in current}
        self.assertEqual(by_id["first"]["latency_ms"], 25)
        self.assertEqual(by_id["second"]["probe_status"], NODE_STATUS_AVAILABLE)

    def test_stale_health_result_is_not_applied_to_replacement_tunnel(self) -> None:
        old_runtime = dict(vpngate_manager.proxy_slots_runtime[0])
        runtime = vpngate_manager.proxy_slots_runtime[0]
        old_process = object()
        replacement_process = object()
        try:
            runtime.update(
                process=old_process,
                active_node_id="old-node",
                connection_generation=10,
                proxy_latency_ms=11,
                connecting=False,
                last_google204_check=0,
            )

            def replace_during_check(_index: int):
                runtime.update(
                    process=replacement_process,
                    active_node_id="replacement-node",
                    connection_generation=11,
                )
                return True, 999, "ok", 0

            with (
                patch.object(vpngate_manager, "slot_process_running", return_value=True),
                patch.object(vpngate_manager, "measure_active_proxy_google204", side_effect=replace_during_check),
            ):
                vpngate_manager.run_active_proxy_google204_check(
                    0, [{"id": "old-node", "country": "Japan"}], now=100,
                )

            self.assertIs(runtime["process"], replacement_process)
            self.assertEqual(runtime["active_node_id"], "replacement-node")
            self.assertEqual(runtime["proxy_latency_ms"], 11)
        finally:
            runtime.clear()
            runtime.update(old_runtime)


class LoggingAndLoginRegressionTests(unittest.TestCase):
    def test_console_log_rotates_while_process_is_running(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "manager.log"
            tee = Tee(str(log_path), max_bytes=1024)
            tee.stdout = io.StringIO()
            try:
                tee.write("a" * 900)
                tee.write("b" * 200)
            finally:
                tee.file.close()

            backup = log_path.with_suffix(".log.1")
            self.assertEqual(backup.read_text(encoding="utf-8"), "a" * 900)
            self.assertEqual(log_path.read_text(encoding="utf-8"), "b" * 200)

    def test_login_preserves_leading_and_trailing_password_whitespace(self) -> None:
        login_html = (Path(__file__).resolve().parents[1] / "web" / "login.html").read_text(encoding="utf-8")
        password_expression = 'document.getElementById("password").value'
        self.assertIn(f"const pwd = {password_expression};", login_html)
        self.assertNotIn(f"{password_expression}.trim()", login_html)

    def test_settings_panel_has_no_api_tls_controls(self) -> None:
        web_dir = Path(__file__).resolve().parents[1] / "web"
        index_html = (web_dir / "index.html").read_text(encoding="utf-8")
        app_js = (web_dir / "app.js").read_text(encoding="utf-8")
        self.assertNotIn('id="api-url"', index_html)
        self.assertNotIn('api-ssl-verify', index_html)
        self.assertNotIn('api_url:', app_js)
        self.assertNotIn('api_ssl_verify', app_js)


class WebRoutingTests(unittest.TestCase):
    def test_root_does_not_redirect_to_secret_path(self) -> None:
        backend = SimpleNamespace(
            load_ui_config=lambda: {
                "secret_path": "safePath",
                "password": "password",
            },
            LOGIN_HTML="<html>login</html>",
            lock=threading.Lock(),
            active_sessions={},
        )
        server = HTTPServer(("127.0.0.1", 0), create_handler(backend))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            root_error: urllib.error.HTTPError | None = None
            try:
                urllib.request.urlopen(f"{base_url}/", timeout=3)
            except urllib.error.HTTPError as exc:
                root_error = exc
            self.assertIsNotNone(root_error)
            self.assertEqual(root_error.code, 404)
            root_error.close()

            with urllib.request.urlopen(f"{base_url}/safePath/", timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(b"login", response.read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


class SchedulerTests(unittest.TestCase):
    def _proxy_config(self) -> dict[str, object]:
        return {
            "proxy_slots": [
                {
                    "enabled": True,
                    "preferred_country": "",
                    "routing_ip_type": "all",
                    "switch_mode": "auto",
                    "last_node_id": "",
                }
                for _ in PROXY_PORTS
            ]
        }

    def test_auto_retest_interval_scales_with_node_pool_size(self) -> None:
        self.assertEqual(vpngate_manager.node_pool_retest_interval_seconds(150), 1500)
        self.assertEqual(vpngate_manager.node_pool_retest_interval_seconds(0), 10)
        self.assertEqual(vpngate_manager.node_pool_retest_interval_seconds(150, 30), 4500)

    def test_auto_proxy_waits_for_initial_node_pool_test(self) -> None:
        old_done = vpngate_manager.initial_node_pool_test_done
        old_runtime = dict(vpngate_manager.proxy_slots_runtime[0])
        try:
            vpngate_manager.initial_node_pool_test_done = False
            vpngate_manager.proxy_slots_runtime[0].update(
                process=None,
                active_node_id="",
                connecting=False,
                error="",
            )
            nodes = [
                {"id": "done", "probe_status": NODE_STATUS_AVAILABLE},
                {"id": "running", "probe_status": NODE_STATUS_TESTING},
                {"id": "pending", "probe_status": NODE_STATUS_QUEUED},
            ]
            with (
                patch.object(vpngate_manager, "load_ui_config", return_value=self._proxy_config()),
                patch.object(vpngate_manager, "read_nodes", return_value=nodes),
                patch.object(vpngate_manager, "slot_process_running", return_value=False),
                patch.object(vpngate_manager, "connect_proxy_slot") as mocked_connect,
            ):
                vpngate_manager.ensure_proxy_slot(0)

            mocked_connect.assert_not_called()
            error = vpngate_manager.proxy_slots_runtime[0]["error"]
            self.assertIn("节点池测试", error)
            self.assertIn("已完成 1/3", error)
            self.assertIn("检测中 1", error)
            self.assertIn("等待测试 1", error)
        finally:
            vpngate_manager.initial_node_pool_test_done = old_done
            vpngate_manager.proxy_slots_runtime[0].clear()
            vpngate_manager.proxy_slots_runtime[0].update(old_runtime)

    def test_probe_progress_text_counts_waiting_nodes(self) -> None:
        progress = vpngate_manager.node_probe_progress_text([
            {"id": "available", "probe_status": NODE_STATUS_AVAILABLE},
            {"id": "unavailable", "probe_status": NODE_STATUS_UNAVAILABLE},
            {"id": "testing", "probe_status": NODE_STATUS_TESTING},
            {"id": "queued", "probe_status": NODE_STATUS_QUEUED},
            {"id": "legacy"},
        ])

        self.assertIn("已完成 2/5", progress)
        self.assertIn("剩余 3", progress)
        self.assertIn("检测中 1", progress)
        self.assertIn("等待测试 2", progress)

    def test_auto_proxy_connects_after_initial_node_pool_test(self) -> None:
        old_done = vpngate_manager.initial_node_pool_test_done
        old_runtime = dict(vpngate_manager.proxy_slots_runtime[0])
        try:
            vpngate_manager.initial_node_pool_test_done = True
            vpngate_manager.proxy_slots_runtime[0].update(
                process=None,
                active_node_id="",
                connecting=False,
                error="",
            )
            nodes = [
                {
                    "id": "fast-node",
                    "probe_status": NODE_STATUS_AVAILABLE,
                    "latency_ms": 30,
                    "latency_source": vpngate_manager.LATENCY_SOURCE,
                    "score": 1,
                }
            ]
            with (
                patch.object(vpngate_manager, "load_ui_config", return_value=self._proxy_config()),
                patch.object(vpngate_manager, "read_nodes", return_value=nodes),
                patch.object(vpngate_manager, "slot_process_running", return_value=False),
                patch.object(vpngate_manager, "connect_proxy_slot") as mocked_connect,
            ):
                vpngate_manager.ensure_proxy_slot(0)

            mocked_connect.assert_called_once_with(0, "fast-node")
        finally:
            vpngate_manager.initial_node_pool_test_done = old_done
            vpngate_manager.proxy_slots_runtime[0].clear()
            vpngate_manager.proxy_slots_runtime[0].update(old_runtime)

    def test_automatic_country_selection_prefers_an_unused_region(self) -> None:
        nodes = [
            {
                "id": "used-japan",
                "country": "Japan",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 10,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
                "score": 100,
            },
            {
                "id": "free-japan",
                "country": "Japan",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 20,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
                "score": 100,
            },
            {
                "id": "free-canada",
                "country": "Canada",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 40,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
                "score": 100,
            },
        ]
        with (
            patch.object(vpngate_manager, "load_ui_config", return_value=self._proxy_config()),
            patch.object(vpngate_manager, "read_nodes", return_value=nodes),
            patch.object(vpngate_manager, "used_node_ids", return_value={"used-japan"}),
        ):
            candidates = vpngate_manager.slot_candidates(0)

        self.assertEqual([node["id"] for node in candidates], ["free-canada", "free-japan"])

    def test_automatic_country_selection_falls_back_to_real_latency(self) -> None:
        nodes = [
            {
                "id": "unverified-fastest",
                "country": "Japan",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 5,
                "latency_source": "legacy-entry-ping",
                "score": 100,
            },
            {
                "id": "japan-slow",
                "country": "Japan",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 80,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
                "score": 100,
            },
            {
                "id": "japan-fast",
                "country": "Japan",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 25,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
                "score": 100,
            },
        ]
        with (
            patch.object(vpngate_manager, "load_ui_config", return_value=self._proxy_config()),
            patch.object(vpngate_manager, "read_nodes", return_value=nodes),
            patch.object(vpngate_manager, "used_node_ids", return_value=set()),
        ):
            candidates = vpngate_manager.slot_candidates(0)

        self.assertEqual([node["id"] for node in candidates], ["japan-fast", "japan-slow"])

    def test_residential_candidates_exclude_hosting_and_use_lowest_latency(self) -> None:
        config = self._proxy_config()
        config["proxy_slots"][0]["routing_ip_type"] = "residential"
        nodes = [
            {
                "id": "hosting-fastest",
                "country": "Japan",
                "ip_type": "hosting",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 5,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
                "score": 100,
            },
            {
                "id": "residential-slow",
                "country": "Japan",
                "ip_type": "residential",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 60,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
                "score": 100,
            },
            {
                "id": "mobile-fast",
                "country": "Japan",
                "ip_type": "mobile",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 30,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
                "score": 100,
            },
        ]
        with (
            patch.object(vpngate_manager, "load_ui_config", return_value=config),
            patch.object(vpngate_manager, "read_nodes", return_value=nodes),
            patch.object(vpngate_manager, "used_node_ids", return_value=set()),
        ):
            candidates = vpngate_manager.slot_candidates(0, "Japan")

        self.assertEqual([node["id"] for node in candidates], ["mobile-fast", "residential-slow"])

    def test_auto_mode_replaces_running_node_that_no_longer_matches_ip_type(self) -> None:
        old_done = vpngate_manager.initial_node_pool_test_done
        old_runtime = dict(vpngate_manager.proxy_slots_runtime[0])
        try:
            vpngate_manager.initial_node_pool_test_done = True
            current = {
                "id": "current-hosting",
                "country": "Japan",
                "ip_type": "hosting",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 10,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
            }
            replacement = {
                "id": "replacement-mobile",
                "country": "Japan",
                "ip_type": "mobile",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 30,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
            }
            config = self._proxy_config()
            config["proxy_slots"][0].update(
                preferred_country="Japan",
                routing_ip_type="residential",
            )
            vpngate_manager.proxy_slots_runtime[0].update(
                active_node_id="current-hosting",
                connecting=False,
                switch_country="",
            )
            with (
                patch.object(vpngate_manager, "load_ui_config", return_value=config),
                patch.object(vpngate_manager, "node_for_runtime", return_value=current),
                patch.object(vpngate_manager, "slot_process_running", return_value=True),
                patch.object(vpngate_manager, "slot_candidates", return_value=[replacement]),
                patch.object(vpngate_manager, "connect_proxy_slot") as mocked_connect,
            ):
                vpngate_manager.ensure_proxy_slot(0)

            mocked_connect.assert_called_once_with(0, "replacement-mobile")
        finally:
            vpngate_manager.initial_node_pool_test_done = old_done
            vpngate_manager.proxy_slots_runtime[0].clear()
            vpngate_manager.proxy_slots_runtime[0].update(old_runtime)

    def test_active_health_latency_does_not_overwrite_batch_pool_latency(self) -> None:
        old_runtime = dict(vpngate_manager.proxy_slots_runtime[0])
        try:
            vpngate_manager.proxy_slots_runtime[0]["active_node_id"] = "active"
            nodes = [{
                "id": "active",
                "probe_status": NODE_STATUS_AVAILABLE,
                "latency_ms": 25,
                "latency_source": vpngate_manager.LATENCY_SOURCE,
            }]
            with (
                patch.object(vpngate_manager, "read_nodes", return_value=nodes),
                patch.object(vpngate_manager, "write_json") as mocked_write,
            ):
                vpngate_manager.update_active_node_latency(0, 900, "live check")

            self.assertEqual(nodes[0]["latency_ms"], 25)
            mocked_write.assert_not_called()
        finally:
            vpngate_manager.proxy_slots_runtime[0].clear()
            vpngate_manager.proxy_slots_runtime[0].update(old_runtime)

    def test_auto_switch_uses_lowest_latency_node_in_failed_region(self) -> None:
        old_done = vpngate_manager.initial_node_pool_test_done
        old_runtime = dict(vpngate_manager.proxy_slots_runtime[0])
        try:
            vpngate_manager.initial_node_pool_test_done = True
            vpngate_manager.proxy_slots_runtime[0].update(
                process=None,
                active_node_id="",
                connecting=False,
                switch_country="Japan",
                error="",
            )
            nodes = [
                {
                    "id": "canada-faster",
                    "country": "Canada",
                    "probe_status": NODE_STATUS_AVAILABLE,
                    "latency_ms": 10,
                    "latency_source": vpngate_manager.LATENCY_SOURCE,
                    "score": 100,
                },
                {
                    "id": "japan-slow",
                    "country": "Japan",
                    "probe_status": NODE_STATUS_AVAILABLE,
                    "latency_ms": 90,
                    "latency_source": vpngate_manager.LATENCY_SOURCE,
                    "score": 100,
                },
                {
                    "id": "japan-fast",
                    "country": "Japan",
                    "probe_status": NODE_STATUS_AVAILABLE,
                    "latency_ms": 30,
                    "latency_source": vpngate_manager.LATENCY_SOURCE,
                    "score": 100,
                },
            ]
            with (
                patch.object(vpngate_manager, "load_ui_config", return_value=self._proxy_config()),
                patch.object(vpngate_manager, "read_nodes", return_value=nodes),
                patch.object(vpngate_manager, "slot_process_running", return_value=False),
                patch.object(vpngate_manager, "connect_proxy_slot") as mocked_connect,
            ):
                vpngate_manager.ensure_proxy_slot(0)

            mocked_connect.assert_called_once_with(0, "japan-fast")
        finally:
            vpngate_manager.initial_node_pool_test_done = old_done
            vpngate_manager.proxy_slots_runtime[0].clear()
            vpngate_manager.proxy_slots_runtime[0].update(old_runtime)

    def test_timeout_switch_remembers_failed_node_region_after_stop(self) -> None:
        old_runtime = dict(vpngate_manager.proxy_slots_runtime[0])
        try:
            runtime = vpngate_manager.proxy_slots_runtime[0]
            runtime.update(
                active_node_id="failed-japan",
                google204_timeout_failures=vpngate_manager.ACTIVE_PROXY_GOOGLE204_TIMEOUT_LIMIT - 1,
                last_google204_check=0,
                switch_country="",
            )
            nodes = [{"id": "failed-japan", "country": "Japan"}]

            def fake_stop(_index: int, _reason: str) -> None:
                runtime.update(active_node_id="", switch_country="")

            with (
                patch.object(vpngate_manager, "slot_process_running", return_value=True),
                patch.object(
                    vpngate_manager,
                    "measure_active_proxy_google204",
                    return_value=(False, 0, "timeout", 1),
                ),
                patch.object(vpngate_manager, "load_ui_config", return_value=self._proxy_config()),
                patch.object(vpngate_manager, "mark_active_node_unavailable"),
                patch.object(vpngate_manager, "stop_proxy_slot", side_effect=fake_stop),
            ):
                vpngate_manager.run_active_proxy_google204_check(0, nodes, now=100)

            self.assertEqual(runtime["switch_country"], "Japan")
        finally:
            vpngate_manager.proxy_slots_runtime[0].clear()
            vpngate_manager.proxy_slots_runtime[0].update(old_runtime)

    def test_active_proxy_google204_retries_immediately_on_timeout(self) -> None:
        with patch.object(
            vpngate_manager,
            "measure_proxy_http_latency",
            side_effect=[
                (False, 0, "Operation timed out after 5000 milliseconds"),
                (False, 0, "Connection timed out"),
            ],
        ) as mocked_measure:
            ok, latency, message, timeout_attempts = vpngate_manager.measure_active_proxy_google204(0)

        self.assertFalse(ok)
        self.assertEqual(latency, 0)
        self.assertIn("二次确认", message)
        self.assertEqual(timeout_attempts, 2)
        self.assertEqual(mocked_measure.call_count, 2)

    def test_active_proxy_google204_does_not_retry_non_timeout_failure(self) -> None:
        with patch.object(
            vpngate_manager,
            "measure_proxy_http_latency",
            return_value=(False, 0, "Google 204 返回异常状态码: 500"),
        ) as mocked_measure:
            ok, latency, _message, timeout_attempts = vpngate_manager.measure_active_proxy_google204(0)

        self.assertFalse(ok)
        self.assertEqual(latency, 0)
        self.assertEqual(timeout_attempts, 0)
        self.assertEqual(mocked_measure.call_count, 1)


class PerformanceRegressionTests(unittest.TestCase):
    def test_performance_setting_validation_rejects_out_of_range_values(self) -> None:
        config = {"node_test_workers": 8}
        self.assertEqual(
            bounded_int_setting({"node_test_workers": 2}, config, "node_test_workers", 8, 1, 8, "并发数"),
            2,
        )
        with self.assertRaisesRegex(ValueError, "必须在 1 到 8 之间"):
            bounded_int_setting({"node_test_workers": 9}, config, "node_test_workers", 8, 1, 8, "并发数")

    def test_successful_web_heartbeats_are_not_written_to_logs(self) -> None:
        self.assertTrue(is_routine_successful_poll("GET", "/secret/api/dashboard", "200"))
        self.assertTrue(is_routine_successful_poll("GET", "/secret/api/traffic?now=1", 200))
        self.assertFalse(is_routine_successful_poll("GET", "/secret/api/dashboard", 500))
        self.assertFalse(is_routine_successful_poll("POST", "/secret/api/dashboard", 200))

    def test_nodes_file_is_parsed_once_until_it_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            nodes_path = Path(temp_dir) / "nodes.json"
            nodes_path.write_text(json.dumps([{"id": "node-1", "config_text": "profile"}]), encoding="utf-8")
            with (
                patch.object(storage, "NODES_FILE", nodes_path),
                patch.object(storage, "_nodes_cache", None),
                patch.object(storage, "_nodes_cache_signature", None),
                patch.object(storage.json, "loads", wraps=json.loads) as mocked_loads,
            ):
                first = storage.read_nodes()
                first[0]["id"] = "mutated-copy"
                second = storage.read_nodes()

        self.assertEqual(mocked_loads.call_count, 1)
        self.assertEqual(second[0]["id"], "node-1")

    def test_recent_logs_are_read_from_the_tail_without_path_read_text(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            logs_dir = data_dir / "logs"
            logs_dir.mkdir()
            log_path = logs_dir / "2026-07-15.json"
            entries = [
                {"epoch": index, "level": "INFO", "module": "Test", "thread": "main", "message": f"line-{index}"}
                for index in range(1000)
            ]
            log_path.write_text(
                "\n".join(json.dumps(entry) for entry in entries) + "\n",
                encoding="utf-8",
            )
            with (
                patch.object(logging_utils, "DATA_DIR", data_dir),
                patch.object(Path, "read_text", side_effect=AssertionError("full-file read is not allowed")),
            ):
                recent = logging_utils.read_log_entries(limit=3)

        self.assertEqual([entry["message"] for entry in recent], ["line-997", "line-998", "line-999"])

    def test_proxy_monitor_reuses_one_nodes_snapshot_per_iteration(self) -> None:
        nodes = [{"id": "cached-node"}]
        config = {"proxy_slots": [{} for _ in PROXY_PORTS]}
        with (
            patch.object(vpngate_manager, "read_nodes", return_value=nodes) as mocked_read_nodes,
            patch.object(vpngate_manager, "load_ui_config", return_value=config) as mocked_load_config,
            patch.object(vpngate_manager, "slot_process_running", return_value=False),
            patch.object(vpngate_manager, "ensure_proxy_slot") as mocked_ensure,
            patch.object(vpngate_manager.time, "sleep", side_effect=SystemExit),
        ):
            with self.assertRaises(SystemExit):
                vpngate_manager.multi_proxy_monitor()

        self.assertEqual(mocked_read_nodes.call_count, 1)
        self.assertEqual(mocked_load_config.call_count, 1)
        self.assertEqual(mocked_ensure.call_count, len(PROXY_PORTS))
        for call in mocked_ensure.call_args_list:
            self.assertIs(call.args[1], nodes)
            self.assertIs(call.args[2], config)

    def test_batch_node_testing_does_not_rewrite_pool_for_every_node(self) -> None:
        nodes = [
            {"id": f"node-{index}", "config_text": "client\n", "probe_status": NODE_STATUS_QUEUED}
            for index in range(20)
        ]
        current_nodes = copy.deepcopy(nodes)
        writes: list[list[dict[str, object]]] = []
        observed_live_statuses: list[set[str]] = []
        old_app = node_testing.APP
        fake_app = SimpleNamespace(
            lock=threading.RLock(),
            node_test_state_lock=threading.Lock(),
            node_test_batch_active=False,
            node_test_cancel_event=None,
            node_test_pending_queue=None,
            set_state=lambda **_updates: None,
        )

        def fake_read_nodes() -> list[dict[str, object]]:
            return copy.deepcopy(current_nodes)

        def fake_write_json(_path: Path, data: list[dict[str, object]]) -> None:
            current_nodes[:] = copy.deepcopy(data)
            writes.append(copy.deepcopy(data))

        def fake_validate(*_args, **_kwargs) -> tuple[bool, int, str]:
            observed_live_statuses.append(set(node_testing.batch_probe_statuses().values()))
            return True, 25, "ok"

        try:
            node_testing.configure_backend(fake_app)
            with tempfile.TemporaryDirectory() as temp_dir:
                with (
                    patch.object(node_testing, "read_nodes", side_effect=fake_read_nodes),
                    patch.object(node_testing, "write_json", side_effect=fake_write_json),
                    patch.object(
                        node_testing,
                        "test_config_path",
                        side_effect=lambda node_id: Path(temp_dir) / f"{node_id}.ovpn",
                    ),
                    patch.object(node_testing, "validate_node_tunnel_latency", side_effect=fake_validate),
                    patch.object(node_testing.vpn_utils, "enrich_ip_info"),
                    patch.object(node_testing, "NODE_TEST_WORKERS", 4),
                    patch.object(node_testing, "NODE_TEST_PERSIST_BATCH_SIZE", 100),
                    patch.object(node_testing, "NODE_TEST_PERSIST_INTERVAL_SECONDS", 60),
                ):
                    results = node_testing.test_multiple_nodes([node["id"] for node in nodes])
        finally:
            node_testing.configure_backend(old_app)
            node_testing.clear_batch_probe_statuses()

        self.assertEqual(len(results), len(nodes))
        self.assertEqual(len(writes), 2)
        self.assertTrue(any(NODE_STATUS_TESTING in statuses for statuses in observed_live_statuses))
        self.assertTrue(all(node["probe_status"] == NODE_STATUS_AVAILABLE for node in current_nodes))


if __name__ == "__main__":
    unittest.main()
