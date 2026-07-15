#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
import sys
import uuid

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server
from vpngate_app.web_api import create_handler

from vpngate_app.config import (
    API_URL, AUTH_FILE, BLACKLIST_FILE, CHECK_INTERVAL_SECONDS, CONFIG_DIR, DATA_DIR,
    DEFAULT_MAX_SCAN_ROWS, DEFAULT_NODE_AUTO_RETEST_SECONDS_PER_NODE,
    DEFAULT_NODE_TEST_WORKERS, DEFAULT_REGION_NODE_LIMIT, INITIAL_CONNECT_TEST_LIMIT,
    INVALID_BACKOFF_SECONDS, LOCAL_PROXY_HOST, MANUAL_TEST_NODE_LIMIT,
    MAX_NODE_AUTO_RETEST_SECONDS_PER_NODE, MAX_NODE_TEST_WORKERS, MAX_REGION_NODE_LIMIT,
    MAX_SCAN_ROWS_LIMIT, MIN_NODE_AUTO_RETEST_SECONDS_PER_NODE, MIN_NODE_TEST_WORKERS,
    MIN_REGION_NODE_LIMIT, MIN_SCAN_ROWS, NODES_FILE,
    OPENVPN_AUTH_PASS, OPENVPN_AUTH_USER, OPENVPN_CMD, OPENVPN_TEST_TIMEOUT_SECONDS,
    PROXY_INTERFACES, PROXY_PORTS, ROOT_DIR, STATE_FILE, UI_HOST, UI_PORT,
    UPSTREAM_PROXY_AUTH_FILE, WEB_DIR, env_int,
)
from vpngate_app.logging_io import Tee
from vpngate_app.logging_utils import log_to_json, read_log_entries
from vpngate_app.storage import load_ui_config, read_json, read_nodes, save_ui_config, write_json
from vpngate_app.traffic import TrafficMonitor
from vpngate_app.node_testing import (
    LATENCY_SOURCE, NODE_STATUS_AVAILABLE, NODE_STATUS_NOT_CHECKED, NODE_STATUS_QUEUED,
    NODE_STATUS_TESTING, NODE_STATUS_UNAVAILABLE, NodeTestCancelled, cancel_active_node_tests,
    configure_backend as configure_node_testing, country_matches,
    batch_probe_statuses,
    measure_proxy_http_latency, migrate_legacy_node_latencies,
    node_test_is_active, normalized_country_name,
    sort_all_nodes, test_multiple_nodes, test_node_by_id,
)
from vpngate_app.openvpn_runtime import (
    configure_state_writer as configure_openvpn_state_writer,
    ensure_dirs, kill_existing_openvpn_processes, run_openvpn_until_ready, stop_process,
)
from vpngate_app.policy_routing import cleanup_policy_routing, setup_policy_routing
from vpngate_app.common import parse_int, safe_name
from vpngate_app.vpngate_source import (
    cached_nodes, configure_state_writer, fetch_api_text, fetch_candidates,
    load_blacklist, row_to_node,
)

lock = threading.RLock()
maintenance_lock = threading.Lock()
active_sessions: dict[str, float] = {}

traffic_monitor = TrafficMonitor(PROXY_INTERFACES)
sample_traffic_slot = traffic_monitor.sample_slot
reset_traffic_stats = traffic_monitor.reset
traffic_slot_payload = traffic_monitor.slot_payload
traffic_state_payload = traffic_monitor.snapshot
traffic_collector_loop = traffic_monitor.run

proxy_slot_locks = [threading.Lock() for _ in PROXY_PORTS]
reserved_node_slots: dict[str, int] = {}
proxy_slots_runtime: list[dict[str, Any]] = [
    {
        "process": None,
        "active_node_id": "",
        "connecting": False,
        "connected_at": 0.0,
        "latency_ms": 0,
        "proxy_ok": False,
        "proxy_ip": "-",
        "proxy_latency_ms": 0,
        "error": "",
        "using_fallback": False,
        "switch_country": "",
        "last_health_check": 0.0,
        "last_google204_check": 0.0,
        "google204_timeout_failures": 0,
    }
    for _ in PROXY_PORTS
]

last_collector_heartbeat = 0.0
initial_node_pool_test_done = False
server_start_time = time.time()
vpn_operation_lock = threading.Lock()
PENDING_NODE_TEST_RETRY_SECONDS = env_int("PENDING_NODE_TEST_RETRY_SECONDS", 10, 1, 300)
ACTIVE_PROXY_GOOGLE204_INTERVAL_SECONDS = env_int("ACTIVE_PROXY_GOOGLE204_INTERVAL_SECONDS", 30, 1, 3600)
ACTIVE_PROXY_GOOGLE204_TIMEOUT_LIMIT = env_int("ACTIVE_PROXY_GOOGLE204_TIMEOUT_LIMIT", 5, 1, 100)
PENDING_NODE_PROBE_STATUSES = (None, NODE_STATUS_QUEUED, NODE_STATUS_NOT_CHECKED, NODE_STATUS_TESTING)
node_test_state_lock = threading.Lock()
node_test_process_lock = threading.Lock()
node_test_batch_active = False
node_test_cancel_event: threading.Event | None = None
node_test_pending_queue: queue.Queue[dict[str, Any]] | None = None
active_node_test_processes: set[subprocess.Popen[str]] = set()
node_refresh_pending = threading.Event()
node_test_start_pending = threading.Event()


def configured_node_test_workers(config: dict[str, Any] | None = None) -> int:
    config = config or load_ui_config()
    return int(config.get("node_test_workers", DEFAULT_NODE_TEST_WORKERS))


def configured_max_scan_rows(config: dict[str, Any] | None = None) -> int:
    config = config or load_ui_config()
    return int(config.get("max_scan_rows", DEFAULT_MAX_SCAN_ROWS))


def configured_node_retest_seconds(config: dict[str, Any] | None = None) -> int:
    config = config or load_ui_config()
    return int(
        config.get(
            "node_auto_retest_seconds_per_node",
            DEFAULT_NODE_AUTO_RETEST_SECONDS_PER_NODE,
        )
    )


def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

configure_state_writer(set_state)
configure_openvpn_state_writer(set_state)
configure_node_testing(sys.modules[__name__])

def get_state() -> dict[str, Any]:
    state = read_json(STATE_FILE, {})
    config = load_ui_config()
    state.pop("password", None)
    state["maintenance_running"] = (
        maintenance_lock.locked()
        or node_refresh_pending.is_set()
        or node_test_start_pending.is_set()
        or node_test_batch_active
    )
    state.setdefault("api_url", API_URL)
    state["fetch_interval_seconds"] = node_pool_retest_interval_seconds(
        seconds_per_node=configured_node_retest_seconds(config)
    )
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    state["proxy_ports"] = list(PROXY_PORTS)
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    return state


WEB_DIR = ROOT_DIR / "web"


def load_web_asset(filename: str) -> str:
    path = WEB_DIR / filename
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Unable to load Web UI asset: {path}") from exc


LOGIN_HTML = load_web_asset("login.html")
INDEX_HTML = load_web_asset("index.html")







def proxy_slot_index(value: Any) -> int:
    try:
        index = int(value) - 1
    except (TypeError, ValueError):
        raise ValueError("代理编号必须是 1 到 5")
    if index < 0 or index >= len(PROXY_PORTS):
        raise ValueError("代理编号必须是 1 到 5")
    return index


def slot_process_running(index: int) -> bool:
    process = proxy_slots_runtime[index].get("process")
    return isinstance(process, subprocess.Popen) and process.poll() is None


def cleanup_slot_policy_routing(index: int) -> None:
    interface = PROXY_INTERFACES[index]
    table = 100 + index
    cleanup_policy_routing(interface, table, 20000 + index)


def setup_slot_policy_routing(index: int) -> None:
    interface = PROXY_INTERFACES[index]
    table = 100 + index
    setup_policy_routing(interface, table, 20000 + index)


def _stop_proxy_slot_locked(index: int, reason: str = "") -> None:
    runtime = proxy_slots_runtime[index]
    sample_traffic_slot(index)
    stop_process(runtime.get("process"))
    cleanup_slot_policy_routing(index)
    runtime.update(
        process=None,
        active_node_id="",
        connecting=False,
        connected_at=0.0,
        latency_ms=0,
        proxy_ok=False,
        proxy_ip="-",
        proxy_latency_ms=0,
        error=reason,
        using_fallback=False,
        switch_country="",
        health_failures=0,
        last_google204_check=0.0,
        google204_timeout_failures=0,
    )


def stop_proxy_slot(index: int, reason: str = "") -> None:
    with proxy_slot_locks[index]:
        _stop_proxy_slot_locked(index, reason)


def stop_all_proxy_slots() -> None:
    for index in range(len(PROXY_PORTS)):
        stop_proxy_slot(index, "服务停止")


def node_for_runtime(index: int, nodes: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    node_id = str(proxy_slots_runtime[index].get("active_node_id") or "")
    if not node_id:
        return None
    source = nodes if nodes is not None else read_nodes()
    return next((node for node in source if node.get("id") == node_id), None)


def used_node_ids(exclude_index: int | None = None) -> set[str]:
    active = {
        str(runtime.get("active_node_id"))
        for index, runtime in enumerate(proxy_slots_runtime)
        if index != exclude_index and runtime.get("active_node_id") and slot_process_running(index)
    }
    with lock:
        active.update(node_id for node_id, index in reserved_node_slots.items() if index != exclude_index)
    return active


def configured_fixed_node_ids(config: dict[str, Any] | None = None) -> set[str]:
    config = config or load_ui_config()
    return {
        str(slot.get("last_node_id"))
        for slot in config.get("proxy_slots", [])
        if slot.get("switch_mode") == "fixed" and slot.get("last_node_id")
    }


def node_matches_ip_type(node: dict[str, Any], ip_type: str) -> bool:
    if ip_type == "residential":
        return node.get("ip_type") in ("residential", "mobile")
    if ip_type == "hosting":
        return node.get("ip_type") == "hosting"
    return True


def slot_candidates(
    index: int,
    country_filter: str = "",
    nodes: list[dict[str, Any]] | None = None,
    config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    slot_config = (config or load_ui_config())["proxy_slots"][index]
    ip_type = str(slot_config.get("routing_ip_type") or "all")
    used = used_node_ids(index)
    nodes = read_nodes() if nodes is None else nodes
    used_countries = {
        normalized_country_name(node.get("country"))
        for node in nodes
        if str(node.get("id") or "") in used and node.get("country")
    }
    candidates = []
    for node in nodes:
        if str(node.get("id") or "") in used or node.get("probe_status") != NODE_STATUS_AVAILABLE:
            continue
        if node.get("latency_source") != LATENCY_SOURCE or parse_int(node.get("latency_ms")) <= 0:
            continue
        if not node_matches_ip_type(node, ip_type):
            continue
        if country_filter and not country_matches(node.get("country"), country_filter):
            continue
        candidates.append(node)
    candidates.sort(
        key=lambda node: (
            0 if country_filter or normalized_country_name(node.get("country")) not in used_countries else 1,
            parse_int(node.get("latency_ms")) or 999999,
            -parse_int(node.get("score")),
        )
    )
    return candidates


def connect_proxy_slot(index: int, node_id: str, update_preference: bool = False) -> str:
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("节点 ID 不能为空")
    if not proxy_slot_locks[index].acquire(blocking=False):
        raise RuntimeError(f"代理 {index + 1} 正在执行连接任务")
    runtime = proxy_slots_runtime[index]
    runtime["connecting"] = True
    runtime["error"] = ""
    reserved = False
    started_new_process = False
    try:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node is None:
            raise ValueError(f"找不到节点: {node_id}")
        if update_preference:
            selection_config = load_ui_config()
            selection_slot = selection_config["proxy_slots"][index]
            if selection_slot.get("switch_mode") == "fixed":
                selection_slot["last_node_id"] = node_id
                selection_slot["enabled"] = True
                save_ui_config(selection_config)
        if node_id in used_node_ids(index):
            raise RuntimeError("该节点已被其他代理端口占用，请选择不同节点")
        with lock:
            reserved_node_slots[node_id] = index
            reserved = True

        with vpn_operation_lock:
            if node_id in used_node_ids(index):
                raise RuntimeError("该节点在等待连接期间已被其他代理端口占用")
            _stop_proxy_slot_locked(index)
            runtime["connecting"] = True
            config_path = CONFIG_DIR / f"proxy_{index + 1}.ovpn"
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(str(node.get("config_text") or ""), encoding="utf-8")
            ok, message, process = run_openvpn_until_ready(
                str(config_path),
                keep_alive=True,
                route_nopull=True,
                timeout=OPENVPN_TEST_TIMEOUT_SECONDS,
                dev=PROXY_INTERFACES[index],
            )
            if not ok or process is None:
                node["probe_status"] = NODE_STATUS_UNAVAILABLE
                node["probe_message"] = message
                node["probed_at"] = time.time()
                write_json(NODES_FILE, sort_all_nodes(nodes))
                raise RuntimeError(message)
            try:
                setup_slot_policy_routing(index)
            except Exception:
                stop_process(process)
                raise
            sample_traffic_slot(index)
            runtime.update(
                process=process,
                active_node_id=node_id,
                connecting=True,
                connected_at=time.time(),
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
            )
            started_new_process = True

        config = load_ui_config()
        slot_config = config["proxy_slots"][index]
        if update_preference:
            slot_config["preferred_country"] = str(node.get("country") or "").strip()
        slot_config["last_node_id"] = node_id
        slot_config["enabled"] = True
        save_ui_config(config)

        preferred_country = str(slot_config.get("preferred_country") or "").strip()
        latency = parse_int(node.get("latency_ms")) if node.get("latency_source") == LATENCY_SOURCE else 0
        runtime.update(
            process=process,
            active_node_id=node_id,
            connecting=True,
            latency_ms=latency,
            proxy_ok=False,
            error="",
            using_fallback=bool(preferred_country and not country_matches(node.get("country"), preferred_country)),
            health_failures=0,
            google204_timeout_failures=0,
            last_google204_check=0.0,
        )
        health = check_proxy_slot_health(index)
        if not health.get("ok"):
            raise RuntimeError(str(health.get("error") or "出口检测失败"))
        latency_ok, latency, latency_message = measure_proxy_http_latency(index)
        if not latency_ok:
            node["latency_ms"] = 0
            node["latency_source"] = LATENCY_SOURCE
            node["probe_status"] = NODE_STATUS_UNAVAILABLE
            node["probe_message"] = latency_message
            node["probed_at"] = time.time()
            write_json(NODES_FILE, sort_all_nodes(nodes))
            raise RuntimeError(latency_message)
        node["probe_status"] = NODE_STATUS_AVAILABLE
        # Keep the comparable latency from the latest full-pool Google 204 test.
        # The just-connected tunnel latency belongs to this active slot only and
        # is exposed through runtime.proxy_latency_ms below.
        write_json(NODES_FILE, sort_all_nodes(nodes))
        runtime.update(
            proxy_ok=True,
            proxy_ip=health.get("ip", "-"),
            proxy_latency_ms=latency,
            latency_ms=latency,
            google204_timeout_failures=0,
            last_google204_check=time.time(),
            switch_country="",
        )
        runtime["connecting"] = False
        log_to_json("INFO", f"Proxy{index + 1}", f"已连接 {node_id}，接口 {PROXY_INTERFACES[index]}，端口 {PROXY_PORTS[index]}")
        return f"代理 {index + 1} 已连接 {normalized_country_name(node.get('country'))} 节点"
    except Exception as exc:
        if started_new_process:
            _stop_proxy_slot_locked(index, str(exc))
        else:
            runtime["connecting"] = False
            runtime["error"] = str(exc)
        raise
    finally:
        if reserved:
            with lock:
                if reserved_node_slots.get(node_id) == index:
                    reserved_node_slots.pop(node_id, None)
        proxy_slot_locks[index].release()


def check_proxy_slot_health(index: int) -> dict[str, Any]:
    runtime = proxy_slots_runtime[index]
    if not slot_process_running(index):
        return {"ok": False, "error": "OpenVPN 进程未运行"}
    interface = PROXY_INTERFACES[index]
    if sys.platform.startswith("linux") and not Path(f"/sys/class/net/{interface}").exists():
        return {"ok": False, "error": f"虚拟网卡 {interface} 不存在"}
    command = [
        "curl", "-sS", "-w", "\n%{time_total} %{http_code}",
        "-x", f"socks5h://127.0.0.1:{PROXY_PORTS[index]}",
        "http://api.ipify.org", "--max-time", "8",
    ]
    username, password = proxy_server.get_proxy_credentials()
    if username is not None and password is not None:
        command.extend(["--proxy-user", f"{username}:{password}"])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().splitlines()
        if result.returncode == 0 and len(lines) >= 2:
            timing, status = lines[-1].split()
            if status == "200" and lines[0].strip():
                return {"ok": True, "ip": lines[0].strip(), "latency_ms": int(float(timing) * 1000)}
        return {"ok": False, "error": result.stderr.strip() or "出口 IP 检测失败"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def node_probe_progress_text(nodes: list[dict[str, Any]] | None = None) -> str:
    nodes = read_nodes() if nodes is None else nodes
    live_statuses = batch_probe_statuses()
    tracked_nodes = [node for node in nodes if node.get("id")]
    total = len(tracked_nodes)
    if not total:
        return "正在获取节点列表..."

    queued = 0
    testing = 0
    available = 0
    unavailable = 0
    for node in tracked_nodes:
        status = live_statuses.get(str(node.get("id") or ""), node.get("probe_status"))
        if status == NODE_STATUS_TESTING:
            testing += 1
        elif status == NODE_STATUS_AVAILABLE:
            available += 1
        elif status == NODE_STATUS_UNAVAILABLE:
            unavailable += 1
        else:
            queued += 1

    completed = available + unavailable
    pending = queued + testing
    percent = int(completed * 100 / total) if total else 0
    return (
        f"已完成 {completed}/{total}（{percent}%），"
        f"剩余 {pending}，检测中 {testing}，等待测试 {queued}，"
        f"可用 {available}，不可用 {unavailable}"
    )


def auto_proxy_connection_wait_reason() -> str:
    with node_test_state_lock:
        if not initial_node_pool_test_done:
            wait_kind = "正在进行初次节点池测试"
        elif node_refresh_pending.is_set():
            wait_kind = "正在更新节点池"
        elif node_test_start_pending.is_set() or node_test_batch_active:
            wait_kind = "正在进行节点连接测试"
        else:
            wait_kind = ""
    if wait_kind:
        return f"{wait_kind}：{node_probe_progress_text()}。"
    return ""


def ensure_proxy_slot(
    index: int,
    nodes: list[dict[str, Any]] | None = None,
    config: dict[str, Any] | None = None,
) -> None:
    if proxy_slots_runtime[index].get("connecting"):
        return
    ui_config = config or load_ui_config()
    slot_config = ui_config["proxy_slots"][index]
    if not slot_config.get("enabled", True):
        if slot_process_running(index):
            stop_proxy_slot(index, "已在面板中停用")
        return
    nodes = read_nodes() if nodes is None else nodes
    current = node_for_runtime(index, nodes)
    wait_reason = auto_proxy_connection_wait_reason()
    if wait_reason:
        if not slot_process_running(index):
            proxy_slots_runtime[index]["error"] = wait_reason
        return
    switch_mode = str(slot_config.get("switch_mode") or "auto")
    if switch_mode == "fixed":
        fixed_node_id = str(slot_config.get("last_node_id") or "")
        if slot_process_running(index) and current and current.get("id") == fixed_node_id:
            proxy_slots_runtime[index]["using_fallback"] = False
            return
        if slot_process_running(index):
            stop_proxy_slot(index, "切换到固定节点模式")
        if not fixed_node_id:
            proxy_slots_runtime[index]["error"] = "固定选中模式尚未选择节点"
            return
        fixed_node = next((node for node in nodes if node.get("id") == fixed_node_id), None)
        if fixed_node is None:
            proxy_slots_runtime[index]["error"] = "固定节点不在缓存池中，请重新选择"
            return
        if fixed_node.get("probe_status") != NODE_STATUS_AVAILABLE:
            proxy_slots_runtime[index]["error"] = "固定节点当前不可用，已停止自动切换"
            return
        if fixed_node_id in used_node_ids(index):
            proxy_slots_runtime[index]["error"] = "固定节点已被其他代理占用"
            return
        try:
            connect_proxy_slot(index, fixed_node_id)
        except Exception as exc:
            proxy_slots_runtime[index]["error"] = f"固定节点连接失败，未切换其他节点：{exc}"
            print(f"[代理 {index + 1}] 固定节点 {fixed_node_id} 连接失败: {exc}", flush=True)
        return

    preferred_country = str(slot_config.get("preferred_country") or "").strip()
    ip_type = str(slot_config.get("routing_ip_type") or "all")
    current_matches = bool(
        current
        and (not preferred_country or country_matches(current.get("country"), preferred_country))
        and node_matches_ip_type(current, ip_type)
    )
    if slot_process_running(index) and current_matches:
        proxy_slots_runtime[index]["using_fallback"] = False
        return

    switch_country = str(proxy_slots_runtime[index].get("switch_country") or "").strip()
    current_country = str(current.get("country") or "").strip() if current else ""
    target_country = preferred_country or switch_country or current_country
    candidates = slot_candidates(index, target_country, nodes, ui_config)
    if not candidates and target_country:
        candidates = slot_candidates(index, nodes=nodes, config=ui_config)
    if slot_process_running(index) and current and candidates and candidates[0].get("id") == current.get("id"):
        proxy_slots_runtime[index]["using_fallback"] = bool(
            preferred_country and not country_matches(current.get("country"), preferred_country)
        )
        return
    last_error = "没有可用节点"
    for candidate in candidates[:3]:
        try:
            connect_proxy_slot(index, str(candidate.get("id") or ""))
            return
        except Exception as exc:
            last_error = str(exc)
            print(f"[代理 {index + 1}] 节点 {candidate.get('id')} 连接失败: {exc}", flush=True)
    proxy_slots_runtime[index]["error"] = last_error


def proxy_slot_payload(index: int, nodes: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    runtime = proxy_slots_runtime[index]
    slot_config = config["proxy_slots"][index]
    node = node_for_runtime(index, nodes)
    running = slot_process_running(index)
    if not slot_config.get("enabled", True):
        status = "disabled"
    elif runtime.get("connecting"):
        status = "connecting"
    elif running and runtime.get("proxy_ok", True):
        status = "connected"
    elif running:
        status = "degraded"
    else:
        status = "disconnected"
    country = normalized_country_name(node.get("country")) if node else "未连接"
    return {
        "id": index + 1,
        "port": PROXY_PORTS[index],
        "interface": PROXY_INTERFACES[index],
        "status": status,
        "active_node_id": runtime.get("active_node_id", ""),
        "node_ip": (node.get("ip") or node.get("remote_host") or "") if node else "",
        "node_port": node.get("remote_port", "") if node else "",
        "node_protocol": str(node.get("proto") or "").upper() if node else "",
        "ip": runtime.get("proxy_ip", "-"),
        "country": country,
        "country_code": node.get("country_short", "") if node else "",
        "location": node.get("location", "") if node else "",
        "latency_ms": runtime.get("proxy_latency_ms") or runtime.get("latency_ms") or 0,
        "node_latency_ms": runtime.get("latency_ms") or 0,
        "owner": (node.get("owner") or node.get("as_name") or "") if node else "",
        "ip_type": node.get("ip_type", "") if node else "",
        "protocols": ["HTTP", "SOCKS5"],
        "preferred_country": slot_config.get("preferred_country", ""),
        "routing_ip_type": slot_config.get("routing_ip_type", "all"),
        "switch_mode": slot_config.get("switch_mode", "auto"),
        "enabled": slot_config.get("enabled", True),
        "using_fallback": bool(runtime.get("using_fallback")),
        "connected_seconds": int(time.time() - runtime["connected_at"]) if running and runtime.get("connected_at") else 0,
        "traffic": traffic_slot_payload(index),
        "error": runtime.get("error", ""),
    }


def country_choice_payloads(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    known_aliases: dict[str, set[str]] = {}
    for alias, translated in vpn_utils.COUNTRY_TRANSLATIONS.items():
        label = normalized_country_name(translated)
        if alias != label:
            known_aliases.setdefault(label, set()).add(alias)
    countries: dict[str, dict[str, Any]] = {}
    for node in nodes:
        country = str(node.get("country") or "").strip()
        if country:
            label = normalized_country_name(country)
            choice = countries.setdefault(
                label,
                {"value": label, "label": label, "count": 0, "aliases": set(known_aliases.get(label, set()))},
            )
            choice["count"] += 1
            if country != label:
                choice["aliases"].add(country)
    country_choices = []
    for choice in sorted(countries.values(), key=lambda item: item["label"]):
        if not choice["aliases"]:
            choice.pop("aliases")
        else:
            choice["aliases"] = sorted(choice["aliases"])
        country_choices.append(choice)
    return country_choices


def multi_dashboard_state() -> dict[str, Any]:
    nodes = read_nodes()
    config = load_ui_config()
    state = read_json(STATE_FILE, {})
    country_choices = country_choice_payloads(nodes)
    node_test_workers = configured_node_test_workers(config)
    max_scan_rows = configured_max_scan_rows(config)
    node_retest_seconds = configured_node_retest_seconds(config)
    return {
        "slots": [proxy_slot_payload(index, nodes, config) for index in range(len(PROXY_PORTS))],
        "countries": country_choices,
        "node_count": len(nodes),
        "region_node_limit": int(config.get("region_node_limit", DEFAULT_REGION_NODE_LIMIT)),
        "node_cache_size": len(country_choices) * int(
            config.get("region_node_limit", DEFAULT_REGION_NODE_LIMIT)
        ),
        "node_cache_count": len(nodes),
        "fetch_interval_seconds": node_pool_retest_interval_seconds(len(nodes), node_retest_seconds),
        "last_fetch_at": state.get("last_fetch_at", 0),
        "last_fetch_candidate_count": state.get("last_fetch_candidate_count", 0),
        "available_node_count": sum(1 for node in nodes if node.get("probe_status") == NODE_STATUS_AVAILABLE),
        "maintenance_running": (
            maintenance_lock.locked()
            or node_refresh_pending.is_set()
            or node_test_start_pending.is_set()
            or node_test_batch_active
        ),
        "node_test_running": node_test_is_active(),
        "node_test_workers": node_test_workers,
        "max_scan_rows": max_scan_rows,
        "node_auto_retest_seconds_per_node": node_retest_seconds,
        "node_refresh_pending": node_refresh_pending.is_set(),
        "username": config.get("username", ""),
        "secret_path": config.get("secret_path", ""),
        "proxy_username": config.get("proxy_username", ""),
        "proxy_password_set": bool(config.get("proxy_password")),
        "proxy_auth_enabled": bool(config.get("proxy_username") or config.get("proxy_password")),
        "uptime_seconds": int(time.time() - server_start_time),
        "last_check_message": state.get("last_check_message", ""),
    }


def public_nodes_for_slot(index: int) -> list[dict[str, Any]]:
    active_by_node = {
        str(runtime.get("active_node_id")): slot_index + 1
        for slot_index, runtime in enumerate(proxy_slots_runtime)
        if runtime.get("active_node_id") and slot_process_running(slot_index)
    }
    live_statuses = batch_probe_statuses()
    result = []
    for node in read_nodes():
        public = {key: value for key, value in node.items() if key not in ("config_text", "config_file")}
        node_id = str(node.get("id") or "")
        if node_id in live_statuses:
            public["probe_status"] = live_statuses[node_id]
        public["active_proxy"] = active_by_node.get(str(node.get("id")), 0)
        public["country_label"] = normalized_country_name(node.get("country"))
        result.append(public)
    return result


NODE_RUNTIME_FIELDS = (
    "latency_ms", "latency_source", "probe_status", "probe_message", "probed_at", "owner",
    "asn", "as_name", "location", "ip_type", "quality",
)


def _node_timestamp(node: dict[str, Any], *keys: str, default: float) -> float:
    for key in keys:
        try:
            value = float(node.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return default


def stage_fetched_node_candidates(
    existing_nodes: list[dict[str, Any]],
    fetched_nodes: list[dict[str, Any]],
    now: float | None = None,
) -> list[dict[str, Any]]:
    """Build an untrimmed old/new union so every candidate can be tested first."""
    now = now or time.time()
    staged: dict[str, dict[str, Any]] = {}
    for source in existing_nodes:
        node_id = str(source.get("id") or "")
        if not node_id:
            continue
        node = dict(source)
        node["_pool_origin"] = "existing"
        staged[node_id] = node
    for source in fetched_nodes:
        node_id = str(source.get("id") or "")
        if not node_id:
            continue
        previous = staged.get(node_id)
        node = dict(source)
        if previous:
            for key in NODE_RUNTIME_FIELDS:
                if key in previous:
                    node[key] = previous[key]
            node["first_fetched_at"] = _node_timestamp(
                previous, "first_fetched_at", "fetched_at", default=now
            )
            node["_pool_origin"] = "existing"
        else:
            node["_pool_origin"] = "new"
        staged[node_id] = node
    return sort_all_nodes(list(staged.values()))


def merge_node_cache(
    existing_nodes: list[dict[str, Any]],
    fetched_nodes: list[dict[str, Any]],
    capacity: int,
    active_node_ids: set[str] | None = None,
    now: float | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Select a per-region pool from an already tested API/cache union."""
    now = now or time.time()
    region_limit = max(MIN_REGION_NODE_LIMIT, min(MAX_REGION_NODE_LIMIT, int(capacity)))
    active_node_ids = {str(node_id) for node_id in (active_node_ids or set()) if node_id}
    merged_by_id: dict[str, dict[str, Any]] = {}
    existing_ids: set[str] = set()

    for source in existing_nodes:
        node_id = str(source.get("id") or "")
        if not node_id:
            continue
        existing_ids.add(node_id)
        node = dict(source)
        last_fetched_at = _node_timestamp(node, "last_fetched_at", "fetched_at", default=now)
        first_fetched_at = _node_timestamp(node, "first_fetched_at", "fetched_at", default=last_fetched_at)
        node["first_fetched_at"] = first_fetched_at
        node["last_fetched_at"] = last_fetched_at
        node["fetched_at"] = last_fetched_at
        merged_by_id[node_id] = node

    new_count = 0
    updated_count = 0
    for source in fetched_nodes:
        node_id = str(source.get("id") or "")
        if not node_id:
            continue
        node = dict(source)
        previous = merged_by_id.get(node_id)
        last_fetched_at = _node_timestamp(node, "last_fetched_at", "fetched_at", default=now)
        if previous:
            updated_count += 1
            for key in NODE_RUNTIME_FIELDS:
                if key in previous:
                    node[key] = previous[key]
            first_fetched_at = _node_timestamp(
                previous, "first_fetched_at", "fetched_at", default=last_fetched_at
            )
        else:
            new_count += 1
            first_fetched_at = _node_timestamp(
                node, "first_fetched_at", "fetched_at", default=last_fetched_at
            )
        node["first_fetched_at"] = first_fetched_at
        node["last_fetched_at"] = last_fetched_at
        node["fetched_at"] = last_fetched_at
        merged_by_id[node_id] = node

    merged = list(merged_by_id.values())
    fetched_ids = {str(node.get("id") or "") for node in fetched_nodes if node.get("id")}
    existing_ids.update(
        str(node.get("id") or "") for node in merged if node.get("_pool_origin") == "existing"
    )
    tagged_new_ids = {
        str(node.get("id") or "") for node in merged if node.get("_pool_origin") == "new"
    }
    new_ids = tagged_new_ids or (fetched_ids - existing_ids)
    groups: dict[str, list[dict[str, Any]]] = {}
    for node in merged:
        region = normalized_country_name(node.get("country")) or str(node.get("country_short") or "未知地区")
        groups.setdefault(region, []).append(node)

    kept: list[dict[str, Any]] = []
    for region_nodes in groups.values():
        protected = [
            node for node in region_nodes
            if str(node.get("id") or "") in active_node_ids or node.get("active")
        ]
        protected_ids = {str(node.get("id") or "") for node in protected}
        selectable = [node for node in region_nodes if str(node.get("id") or "") not in protected_ids]
        available = [node for node in selectable if node.get("probe_status") == NODE_STATUS_AVAILABLE]
        available_sort_key = lambda node: (
            # A tested new node consumes replacement quota first; among the
            # remaining old nodes, the slowest one is therefore displaced.
            0 if str(node.get("id") or "") in new_ids else 1,
            parse_int(node.get("latency_ms")) or 999999,
            -parse_int(node.get("score")),
        )
        available.sort(key=available_sort_key)
        slots_left = max(0, region_limit - len(protected))
        residential_target = (region_limit + 1) // 2
        protected_residential = sum(
            1 for node in protected if node.get("ip_type") in ("residential", "mobile")
        )
        residential_slots = min(
            slots_left,
            max(0, residential_target - protected_residential),
        )
        residential_available = [
            node for node in available if node.get("ip_type") in ("residential", "mobile")
        ]
        selected = residential_available[:residential_slots]
        selected_ids = {str(node.get("id") or "") for node in selected}
        remaining_available = [
            node for node in available if str(node.get("id") or "") not in selected_ids
        ]
        selected.extend(remaining_available[:max(0, slots_left - len(selected))])
        slots_left -= len(selected)
        if slots_left:
            has_available = any(node.get("probe_status") == NODE_STATUS_AVAILABLE for node in region_nodes)
            fallback = [node for node in selectable if node not in selected]
            fallback.sort(key=lambda node: (
                # When an entire region failed, rotate in the newly fetched snapshot.
                (0 if str(node.get("id") or "") in new_ids else 1)
                if not has_available else
                (0 if str(node.get("id") or "") in existing_ids else 1),
                0 if node.get("probe_status") in PENDING_NODE_PROBE_STATUSES else 1,
                -_node_timestamp(node, "last_fetched_at", "fetched_at", default=now),
                -parse_int(node.get("score")),
            ))
            current_residential = protected_residential + sum(
                1 for node in selected if node.get("ip_type") in ("residential", "mobile")
            )
            fallback_residential_slots = min(
                slots_left,
                max(0, residential_target - current_residential),
            )
            residential_fallback = [
                node for node in fallback if node.get("ip_type") in ("residential", "mobile")
            ]
            chosen_residential_fallback = residential_fallback[:fallback_residential_slots]
            selected.extend(chosen_residential_fallback)
            selected_ids.update(str(node.get("id") or "") for node in selected)
            fallback = [
                node for node in fallback if str(node.get("id") or "") not in selected_ids
            ]
            slots_left -= len(chosen_residential_fallback)
            selected.extend(fallback[:slots_left])
        kept.extend(protected + selected)

    kept_ids = {str(node.get("id") or "") for node in kept}
    evicted = [node for node in merged if str(node.get("id") or "") not in kept_ids]
    for node in kept:
        node.pop("_pool_origin", None)
    stats = {
        "capacity": region_limit * len(groups),
        "region_limit": region_limit,
        "region_count": len(groups),
        "fetched_count": len(fetched_nodes),
        "new_count": len(new_ids),
        "updated_count": len(fetched_ids & existing_ids),
        "evicted_count": len(evicted),
        "evicted_unavailable": sum(1 for node in evicted if node.get("probe_status") == NODE_STATUS_UNAVAILABLE),
        "evicted_slow": sum(
            1 for node in evicted
            if node.get("probe_status") == NODE_STATUS_AVAILABLE and parse_int(node.get("latency_ms")) > 0
        ),
        "replaced_old": sum(1 for node in evicted if str(node.get("id") or "") in existing_ids),
        "pool_size": len(kept),
    }
    return sort_all_nodes(kept), stats


def merge_fetched_nodes(fetched: list[dict[str, Any]], capacity: int) -> list[dict[str, Any]]:
    protected_ids = used_node_ids() | configured_fixed_node_ids()
    merged, stats = merge_node_cache(read_nodes(), fetched, capacity, protected_ids)
    write_json(NODES_FILE, merged)
    set_state(
        region_node_limit=stats["region_limit"],
        node_cache_size=stats["capacity"],
        node_cache_count=stats["pool_size"],
        last_fetch_candidate_count=stats["fetched_count"],
        last_cache_new_count=stats["new_count"],
        last_cache_evicted_count=stats["evicted_count"],
        last_cache_evicted_unavailable=stats["evicted_unavailable"],
        last_cache_evicted_slow=stats["evicted_slow"],
    )
    return merged


def resize_node_cache(capacity: int) -> dict[str, int]:
    protected_ids = used_node_ids() | configured_fixed_node_ids()
    resized, stats = merge_node_cache(read_nodes(), [], capacity, protected_ids)
    write_json(NODES_FILE, resized)
    set_state(
        region_node_limit=stats["region_limit"],
        node_cache_size=stats["capacity"],
        node_cache_count=stats["pool_size"],
    )
    return stats


def resize_node_cache_when_idle(capacity: int) -> None:
    with maintenance_lock:
        resize_node_cache(capacity)


def node_pool_retest_interval_seconds(
    node_count: int | None = None,
    seconds_per_node: int = DEFAULT_NODE_AUTO_RETEST_SECONDS_PER_NODE,
) -> int:
    if node_count is None:
        try:
            node_count = len(read_nodes())
        except Exception:
            node_count = 0
    return max(1, int(node_count or 0)) * max(1, int(seconds_per_node))


def google204_failure_is_timeout(message: Any) -> bool:
    text = str(message or "").lower()
    return any(
        marker in text
        for marker in (
            "timeout",
            "timed out",
            "operation timed out",
            "connection timed out",
            "超时",
        )
    )


def measure_active_proxy_google204(index: int) -> tuple[bool, int, str, int]:
    ok, latency, message = measure_proxy_http_latency(index)
    if ok:
        return True, latency, message, 0
    if not google204_failure_is_timeout(message):
        return False, 0, message, 0

    retry_ok, retry_latency, retry_message = measure_proxy_http_latency(index)
    if retry_ok:
        return True, retry_latency, retry_message, 0
    combined_message = f"{message}；二次确认: {retry_message}"
    if google204_failure_is_timeout(retry_message):
        return False, 0, combined_message, 2
    return False, 0, combined_message, 0


def mark_active_node_unavailable(index: int, message: str) -> None:
    node_id = str(proxy_slots_runtime[index].get("active_node_id") or "")
    if not node_id:
        return
    current_nodes = read_nodes()
    for node in current_nodes:
        if str(node.get("id") or "") == node_id:
            node["probe_status"] = NODE_STATUS_UNAVAILABLE
            node["probe_message"] = message
            node["latency_ms"] = 0
            node["latency_source"] = LATENCY_SOURCE
            node["probed_at"] = time.time()
            write_json(NODES_FILE, sort_all_nodes(current_nodes))
            return


def update_active_node_latency(index: int, latency: int, message: str) -> None:
    node_id = str(proxy_slots_runtime[index].get("active_node_id") or "")
    if not node_id:
        return
    current_nodes = read_nodes()
    for node in current_nodes:
        if str(node.get("id") or "") == node_id:
            # Pool latencies must remain from the same batch test so candidates
            # stay comparable. Only repair legacy/missing probe data here; the
            # active slot's live latency is kept in proxy_slots_runtime.
            if (
                node.get("probe_status") != NODE_STATUS_AVAILABLE
                or node.get("latency_source") != LATENCY_SOURCE
                or parse_int(node.get("latency_ms")) <= 0
            ):
                node["latency_ms"] = latency
                node["latency_source"] = LATENCY_SOURCE
                node["probe_status"] = NODE_STATUS_AVAILABLE
                node["probe_message"] = message
                node["probed_at"] = time.time()
                write_json(NODES_FILE, sort_all_nodes(current_nodes))
            return


def node_probe_is_pending(node: dict[str, Any]) -> bool:
    return node.get("probe_status") in PENDING_NODE_PROBE_STATUSES


def pending_probe_count_from_nodes(nodes: list[dict[str, Any]]) -> int:
    return sum(1 for node in nodes if node_probe_is_pending(node))


def pending_probe_count() -> int:
    return pending_probe_count_from_nodes(read_nodes())


def _node_probed_age_seconds(node: dict[str, Any], now: float) -> float:
    try:
        probed_at = float(node.get("probed_at") or 0)
    except (TypeError, ValueError):
        probed_at = 0.0
    return now - probed_at


def probe_candidate_node_ids(
    nodes: list[dict[str, Any]],
    preferred: list[str],
    *,
    full_pool: bool = False,
    include_unavailable_backoff: bool = False,
) -> list[str]:
    now = time.time()
    candidates: list[dict[str, Any]] = []
    for node in nodes:
        if not node.get("id"):
            continue
        status = node.get("probe_status")
        if full_pool or status in PENDING_NODE_PROBE_STATUSES:
            candidates.append(node)
        elif (
            include_unavailable_backoff
            and status == NODE_STATUS_UNAVAILABLE
            and _node_probed_age_seconds(node, now) >= INVALID_BACKOFF_SECONDS
        ):
            candidates.append(node)

    candidates.sort(
        key=lambda node: (
            0 if any(country and country_matches(node.get("country"), country) for country in preferred) else 1,
            -parse_int(node.get("score")),
            parse_int(node.get("ping")) or 999999,
        )
    )
    return [str(node.get("id")) for node in candidates if node.get("id")]


def continue_pending_node_tests(wait: bool = False) -> str:
    global initial_node_pool_test_done
    if not maintenance_lock.acquire(blocking=wait):
        return "节点维护任务正在运行"
    try:
        if node_refresh_pending.is_set():
            return "节点更新任务正在等待执行，暂不续测排队节点"

        config = load_ui_config()
        worker_count = configured_node_test_workers(config)
        preferred = [str(slot.get("preferred_country") or "") for slot in config["proxy_slots"]]
        nodes = read_nodes()
        node_ids = probe_candidate_node_ids(nodes, preferred)
        if not node_ids:
            message = "没有需要续测的排队节点"
            set_state(last_check_message=message)
            if pending_probe_count_from_nodes(nodes) == 0:
                initial_node_pool_test_done = True
            return message

        set_state(last_check_message=f"发现 {len(node_ids)} 个排队节点，继续使用 {worker_count} 线程检测...")
        with vpn_operation_lock:
            test_multiple_nodes(node_ids, worker_count)

        for index in range(len(PROXY_PORTS)):
            ensure_proxy_slot(index)

        current_nodes = read_nodes()
        remaining = pending_probe_count_from_nodes(current_nodes)
        if remaining:
            message = (
                f"排队节点续测阶段完成：本轮检测 {len(node_ids)} 个，"
                f"仍有 {remaining} 个节点等待下一轮续测"
            )
        else:
            initial_node_pool_test_done = True
            message = f"排队节点续测完成：{len(current_nodes)} 个节点均已得到检测结果"
        set_state(last_check_message=message)
        return message
    except NodeTestCancelled:
        message = "排队节点续测已取消，等待更新节点"
        set_state(last_check_message=message)
        return message
    finally:
        maintenance_lock.release()


def multi_maintain_nodes(force: bool = False, wait: bool = False) -> str:
    global last_collector_heartbeat, initial_node_pool_test_done
    if not maintenance_lock.acquire(blocking=wait):
        return "节点维护任务正在运行"
    try:
        last_collector_heartbeat = time.time()
        existing_snapshot = read_nodes()
        config = load_ui_config()
        worker_count = configured_node_test_workers(config)
        max_scan_rows = configured_max_scan_rows(config)
        set_state(last_check_message="正在获取 VPNGate 节点列表；新旧节点全部测试后再按地区更新节点池...")
        fetched: list[dict[str, Any]] = []
        fetch_error: Exception | None = None
        try:
            fetched = fetch_candidates(max_scan_rows)
        except Exception as exc:
            fetch_error = exc
            if not existing_snapshot:
                raise
            log_to_json("WARNING", "NodePool", f"节点拉取失败，保留本地节点池并继续启动检测: {exc}")
            set_state(last_check_message=f"节点拉取失败，保留 {len(existing_snapshot)} 个本地节点并进行连接测试...")
        region_limit = int(config.get("region_node_limit", DEFAULT_REGION_NODE_LIMIT))
        staged_refresh = bool(fetched)
        if staged_refresh:
            nodes = stage_fetched_node_candidates(existing_snapshot, fetched)
            write_json(NODES_FILE, nodes)
            set_state(
                last_fetch_candidate_count=len(fetched),
                last_check_message=(
                    f"已暂存 {len(existing_snapshot)} 个本地节点和 {len(fetched)} 个拉取结果，"
                    f"正在对 {len(nodes)} 个去重节点进行 Google 204 测试..."
                ),
            )
        else:
            nodes = existing_snapshot
        preferred = [str(slot.get("preferred_country") or "") for slot in config["proxy_slots"]]
        full_pool_test = staged_refresh or force or not initial_node_pool_test_done
        node_ids = probe_candidate_node_ids(
            nodes,
            preferred,
            full_pool=full_pool_test,
            include_unavailable_backoff=not full_pool_test,
        )
        if node_ids:
            with vpn_operation_lock:
                test_multiple_nodes(node_ids, worker_count)
        if staged_refresh:
            protected_ids = used_node_ids() | configured_fixed_node_ids(config)
            finalized, stats = merge_node_cache([], read_nodes(), region_limit, protected_ids)
            write_json(NODES_FILE, finalized)
            set_state(
                region_node_limit=stats["region_limit"],
                node_cache_size=stats["capacity"],
                node_cache_count=stats["pool_size"],
                last_cache_new_count=stats["new_count"],
                last_cache_evicted_count=stats["evicted_count"],
                last_cache_evicted_unavailable=stats["evicted_unavailable"],
                last_cache_evicted_slow=stats["evicted_slow"],
                last_cache_replaced_old=stats["replaced_old"],
            )
            log_to_json(
                "INFO", "NodePool",
                f"地区节点池更新完成：{stats['region_count']} 个地区，每地区最多 {region_limit} 个，"
                f"保留 {stats['pool_size']} 个，替换旧节点 {stats['replaced_old']} 个",
            )
        if full_pool_test:
            initial_node_pool_test_done = True
        for index in range(len(PROXY_PORTS)):
            ensure_proxy_slot(index)
        current_nodes = read_nodes()
        remaining = pending_probe_count_from_nodes(current_nodes)
        if remaining:
            message = (
                f"节点维护阶段完成：共 {len(current_nodes)} 个节点，"
                f"本轮并发检测 {len(node_ids)} 个，剩余 {remaining} 个将在后续维护中继续检测"
            )
        else:
            suffix = f"；API 拉取失败但本地池已保留 ({fetch_error})" if fetch_error else ""
            message = f"节点维护完成：{len(current_nodes)} 个节点均已由 {worker_count} 个工作线程检测{suffix}"
        set_state(last_check_message=message)
        return message
    except NodeTestCancelled:
        if 'staged_refresh' in locals() and staged_refresh:
            write_json(NODES_FILE, existing_snapshot)
        message = "节点测试已取消，正在切换到更新节点流程"
        set_state(last_check_message=message)
        return message
    except Exception:
        if 'staged_refresh' in locals() and staged_refresh:
            write_json(NODES_FILE, existing_snapshot)
        raise
    finally:
        maintenance_lock.release()


def test_cached_node_pool() -> str:
    if not maintenance_lock.acquire(blocking=False):
        return "节点维护任务正在运行"
    try:
        if node_refresh_pending.is_set():
            return "连接测试已让路给更新节点"
        config = load_ui_config()
        worker_count = configured_node_test_workers(config)
        nodes = read_nodes()
        node_ids = [
            str(node.get("id")) for node in nodes
            if node.get("id")
        ]
        set_state(last_check_message=f"正在测试缓存池连接：共 {len(node_ids)} 个节点，{worker_count} 线程并发执行")
        if node_ids:
            with vpn_operation_lock:
                test_multiple_nodes(node_ids, worker_count)
        for index in range(len(PROXY_PORTS)):
            ensure_proxy_slot(index)
        current_nodes = read_nodes()
        available = sum(1 for node in current_nodes if node.get("probe_status") == NODE_STATUS_AVAILABLE)
        unavailable = sum(1 for node in current_nodes if node.get("probe_status") == NODE_STATUS_UNAVAILABLE)
        message = (
            f"缓存池连接测试完成：并发检测 {len(node_ids)} 个节点，"
            f"可用 {available} 个，不可用 {unavailable} 个"
        )
        set_state(last_check_message=message)
        return message
    except NodeTestCancelled:
        message = "缓存池连接测试已取消，等待更新节点"
        set_state(last_check_message=message)
        return message
    finally:
        maintenance_lock.release()


def _scheduled_node_refresh() -> None:
    try:
        multi_maintain_nodes(True, wait=True)
    finally:
        node_refresh_pending.clear()


def _scheduled_cached_node_test() -> None:
    try:
        test_cached_node_pool()
    finally:
        node_test_start_pending.clear()


def schedule_cached_node_test() -> bool:
    with node_test_state_lock:
        if (
            node_test_batch_active
            or node_test_start_pending.is_set()
            or node_refresh_pending.is_set()
            or maintenance_lock.locked()
        ):
            return False
        node_test_start_pending.set()
    threading.Thread(target=_scheduled_cached_node_test, name="cached-node-test", daemon=True).start()
    return True


def schedule_node_refresh() -> bool:
    with node_test_state_lock:
        if node_refresh_pending.is_set():
            return False
        node_refresh_pending.set()
    threading.Thread(target=_scheduled_node_refresh, name="node-refresh", daemon=True).start()
    return True


def run_active_proxy_google204_check(index: int, nodes: list[dict[str, Any]], now: float | None = None) -> None:
    runtime = proxy_slots_runtime[index]
    if not slot_process_running(index):
        return
    now = time.time() if now is None else now
    last_check = float(runtime.get("last_google204_check") or 0)
    if last_check and now - last_check < ACTIVE_PROXY_GOOGLE204_INTERVAL_SECONDS:
        return

    node = node_for_runtime(index, nodes)
    if node:
        runtime["latency_ms"] = (
            parse_int(node.get("latency_ms"))
            if node.get("latency_source") == LATENCY_SOURCE else 0
        )

    ok, latency, message, timeout_attempts = measure_active_proxy_google204(index)
    checked_at = time.time()
    runtime["last_health_check"] = checked_at
    runtime["last_google204_check"] = checked_at

    if ok:
        runtime.update(
            proxy_ok=True,
            proxy_latency_ms=latency,
            latency_ms=latency,
            error="",
            health_failures=0,
            google204_timeout_failures=0,
        )
        update_active_node_latency(index, latency, message)
        return

    runtime["proxy_ok"] = False
    runtime["error"] = str(message or "Google 204 检测失败")
    runtime["health_failures"] = int(runtime.get("health_failures") or 0) + 1

    if not timeout_attempts:
        runtime["google204_timeout_failures"] = 0
        return

    timeout_failures = int(runtime.get("google204_timeout_failures") or 0) + timeout_attempts
    runtime["google204_timeout_failures"] = timeout_failures
    runtime["error"] = f"Google 204 连续超时 {timeout_failures} 次: {message}"

    config = load_ui_config()["proxy_slots"][index]
    if timeout_failures >= ACTIVE_PROXY_GOOGLE204_TIMEOUT_LIMIT:
        if str(config.get("switch_mode") or "auto") == "auto":
            switch_message = (
                f"Google 204 连续超时 {timeout_failures} 次，"
                "已标记当前节点不可用并自动切换"
            )
            failed_node = node_for_runtime(index, nodes)
            switch_country = str(failed_node.get("country") or "").strip() if failed_node else ""
            mark_active_node_unavailable(index, switch_message)
            stop_proxy_slot(index, switch_message)
            runtime["switch_country"] = switch_country
        else:
            runtime["error"] = (
                f"Google 204 连续超时 {timeout_failures} 次，"
                "固定选中模式不自动切换"
            )


def multi_collector_loop() -> None:
    first_run = True
    while True:
        try:
            has_pending_nodes = pending_probe_count() > 0
            if (
                not first_run
                and has_pending_nodes
                and not node_refresh_pending.is_set()
                and not node_test_start_pending.is_set()
                and not maintenance_lock.locked()
            ):
                continue_pending_node_tests(False)
            elif not (node_refresh_pending.is_set() or node_test_start_pending.is_set() or maintenance_lock.locked()):
                multi_maintain_nodes(force=not first_run)
                first_run = False
        except Exception as exc:
            print(f"[多代理节点维护] {exc}", flush=True)
            set_state(last_check_message=f"节点维护失败: {exc}")
        config = load_ui_config()
        delay = (
            PENDING_NODE_TEST_RETRY_SECONDS
            if pending_probe_count()
            else node_pool_retest_interval_seconds(
                seconds_per_node=configured_node_retest_seconds(config)
            )
        )
        time.sleep(delay)


def multi_proxy_monitor() -> None:
    while True:
        try:
            nodes = read_nodes()
            config = load_ui_config()
            for index in range(len(PROXY_PORTS)):
                runtime = proxy_slots_runtime[index]
                if runtime.get("connecting"):
                    continue
                was_running = slot_process_running(index)
                if was_running:
                    run_active_proxy_google204_check(index, nodes)
                if was_running and not slot_process_running(index):
                    # A failed health check may have changed the node status on disk.
                    nodes = read_nodes()
                ensure_proxy_slot(index, nodes, config)
        except Exception as exc:
            print(f"[多代理守护] {exc}", flush=True)
        time.sleep(1)



def main() -> None:
    ensure_dirs()
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee
    kill_existing_openvpn_processes()

    migrated_latency_records = migrate_legacy_node_latencies()
    if migrated_latency_records:
        print(f"[节点延时] 已清除 {migrated_latency_records} 条旧入口延时记录，等待 Google 204 隧道重测", flush=True)

    def shutdown_handler(signum: int, frame: Any) -> None:
        print(f"[系统] 收到信号 {signum}，正在关闭 5 个代理隧道...", flush=True)
        stop_all_proxy_slots()
        raise SystemExit(0)

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, shutdown_handler)
        signal.signal(signal.SIGINT, shutdown_handler)

    ui_config = load_ui_config()
    worker_count = configured_node_test_workers(ui_config)
    node_retest_seconds = configured_node_retest_seconds(ui_config)
    proxy_server.set_proxy_credentials(
        str(ui_config.get("proxy_username") or ""),
        str(ui_config.get("proxy_password") or ""),
    )
    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "proxy_ports": list(PROXY_PORTS),
            "fetch_interval_seconds": node_pool_retest_interval_seconds(0, node_retest_seconds),
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "last_fetch_status": "starting",
            "last_check_message": f"服务已启动，正在获取并使用 {worker_count} 个工作线程检测 VPN 节点...",
        },
    )

    for port, interface in zip(PROXY_PORTS, PROXY_INTERFACES):
        threading.Thread(
            target=proxy_server.start_proxy_server,
            args=(LOCAL_PROXY_HOST, port, interface),
            daemon=True,
        ).start()

    ready_ports: set[int] = set()
    for _ in range(30):
        for port in PROXY_PORTS:
            if port in ready_ports:
                continue
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    ready_ports.add(port)
            except OSError:
                pass
        if len(ready_ports) == len(PROXY_PORTS):
            break
        time.sleep(0.5)
    if len(ready_ports) != len(PROXY_PORTS):
        print(f"[警告] 仅有这些代理端口启动成功: {sorted(ready_ports)}", flush=True)

    threading.Thread(target=traffic_collector_loop, name="traffic-collector", daemon=True).start()
    threading.Thread(target=multi_collector_loop, daemon=True).start()
    threading.Thread(target=multi_proxy_monitor, daemon=True).start()

    print(f"UI: http://{UI_HOST}:{UI_PORT}/", flush=True)
    print(f"Proxy ports: {', '.join(str(port) for port in PROXY_PORTS)}", flush=True)
    DualStackHTTPServer((UI_HOST, UI_PORT), create_handler(sys.modules[__name__])).serve_forever()


if __name__ == "__main__":
    main()
