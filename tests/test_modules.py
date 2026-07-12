from __future__ import annotations

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

from vpngate_app.config import PROXY_INTERFACES, PROXY_PORTS
from vpngate_app import node_testing
from vpngate_app import openvpn_runtime, policy_routing
from vpngate_app.node_testing import (
    NODE_STATUS_AVAILABLE, NODE_STATUS_QUEUED, NODE_STATUS_TESTING,
    NODE_STATUS_UNAVAILABLE, sort_all_nodes,
)
from vpngate_app.storage import normalize_proxy_slots
from vpngate_app.traffic import TrafficMonitor
from vpngate_app.web_api import create_handler
import vpngate_manager


class ConfigTests(unittest.TestCase):
    def test_fixed_proxy_layout(self) -> None:
        self.assertEqual(PROXY_PORTS, (7928, 7929, 7930, 7931, 7932))
        self.assertEqual(PROXY_INTERFACES, ("tun0", "tun1", "tun2", "tun3", "tun4"))

    def test_slot_normalization_rejects_unknown_modes(self) -> None:
        slots = normalize_proxy_slots([{"routing_ip_type": "unknown", "switch_mode": "unknown"}])
        self.assertEqual(len(slots), 5)
        self.assertEqual(slots[0]["routing_ip_type"], "all")
        self.assertEqual(slots[0]["switch_mode"], "auto")


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
                patch.object(vpngate_manager, "fetch_candidates", side_effect=RuntimeError("offline")),
                patch.object(vpngate_manager, "load_ui_config", return_value={"region_node_limit": 2, "proxy_slots": [{} for _ in PROXY_PORTS]}),
                patch.object(vpngate_manager, "test_multiple_nodes") as test_nodes,
                patch.object(vpngate_manager, "ensure_proxy_slot"),
                patch.object(vpngate_manager, "pending_probe_count_from_nodes", return_value=0),
                patch.object(vpngate_manager, "set_state"),
                patch.object(vpngate_manager, "log_to_json"),
            ):
                message = vpngate_manager.multi_maintain_nodes(force=True, wait=True)
            test_nodes.assert_called_once_with(["old"])
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


if __name__ == "__main__":
    unittest.main()
