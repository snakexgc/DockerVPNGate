from __future__ import annotations

import json
import queue
import socket
import subprocess
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any

import proxy_server
import vpn_utils
from .common import parse_int, safe_name
from .config import (
    API_URL, CHECK_INTERVAL_SECONDS, CONFIG_DIR, FETCH_INTERVAL_SECONDS,
    MAX_NODE_TEST_WORKERS, MIN_NODE_TEST_WORKERS,
    NODES_FILE, NODE_TEST_PERSIST_BATCH_SIZE, NODE_TEST_PERSIST_INTERVAL_SECONDS,
    NODE_TEST_WORKERS, OPENVPN_TEST_TIMEOUT_SECONDS, PROXY_PORTS, STATE_FILE,
)
from .openvpn_runtime import run_openvpn_until_ready, stop_process
from .policy_routing import cleanup_policy_routing, setup_policy_routing
from .storage import read_json, read_nodes, write_json

APP: ModuleType


def configure_backend(backend: ModuleType) -> None:
    global APP
    APP = backend

NODE_STATUS_QUEUED = "queued"
NODE_STATUS_TESTING = "testing"
NODE_STATUS_AVAILABLE = "available"
NODE_STATUS_UNAVAILABLE = "unavailable"
NODE_STATUS_NOT_CHECKED = "not_checked"

class NodeTestCancelled(RuntimeError):
    pass


def node_test_is_active() -> bool:
    with APP.node_test_state_lock:
        return APP.node_test_batch_active


def register_node_test_process(process: subprocess.Popen[str]) -> None:
    with APP.node_test_process_lock:
        APP.active_node_test_processes.add(process)


def unregister_node_test_process(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    with APP.node_test_process_lock:
        APP.active_node_test_processes.discard(process)


def cancel_active_node_tests() -> bool:
    with APP.node_test_state_lock:
        if not APP.node_test_batch_active or APP.node_test_cancel_event is None:
            return False
        APP.node_test_cancel_event.set()
        pending = APP.node_test_pending_queue
    if pending is not None:
        while True:
            try:
                pending.get_nowait()
                pending.task_done()
            except queue.Empty:
                break
    with APP.node_test_process_lock:
        processes = list(APP.active_node_test_processes)
    for process in processes:
        try:
            if process.poll() is None:
                process.terminate()
        except OSError:
            pass
    APP.set_state(last_check_message="已取消当前节点测试，正在等待更新节点")
    return True

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == NODE_STATUS_AVAILABLE or n.get("active")],
        key=lambda n: (
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [
            n for n in nodes
            if n.get("probe_status") in (NODE_STATUS_QUEUED, NODE_STATUS_NOT_CHECKED, NODE_STATUS_TESTING)
            and not n.get("active")
        ],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == NODE_STATUS_UNAVAILABLE and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes


def normalized_country_name(country: Any) -> str:
    value = str(country or "").strip()
    return vpn_utils.COUNTRY_TRANSLATIONS.get(value, value)

def country_matches(node_country: Any, target_country: Any) -> bool:
    return bool(target_country) and normalized_country_name(node_country) == normalized_country_name(target_country)






active_test_indexes = set()
test_indexes_lock = threading.Lock()
batch_probe_status_lock = threading.Lock()
batch_probe_status: dict[str, str] = {}
single_node_test_lock = threading.Lock()
single_node_test_generation = 0
single_node_test_cancel_event: threading.Event | None = None
single_node_test_processes: set[subprocess.Popen[str]] = set()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(10, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)


def batch_probe_statuses() -> dict[str, str]:
    with batch_probe_status_lock:
        return dict(batch_probe_status)


def set_batch_probe_status(node_id: str, status: str) -> None:
    with batch_probe_status_lock:
        batch_probe_status[node_id] = status


def clear_batch_probe_statuses() -> None:
    with batch_probe_status_lock:
        batch_probe_status.clear()

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"


def _terminate_processes(processes: list[subprocess.Popen[str]]) -> None:
    for process in processes:
        try:
            if process.poll() is None:
                process.terminate()
        except OSError:
            pass


def begin_single_node_test() -> tuple[int, threading.Event]:
    global single_node_test_generation, single_node_test_cancel_event, single_node_test_processes
    with single_node_test_lock:
        previous_event = single_node_test_cancel_event
        previous_processes = list(single_node_test_processes)
        if previous_event is not None:
            previous_event.set()
        single_node_test_processes = set()
        single_node_test_generation += 1
        generation = single_node_test_generation
        single_node_test_cancel_event = threading.Event()
        cancel_event = single_node_test_cancel_event
    _terminate_processes(previous_processes)
    return generation, cancel_event


def register_single_node_test_process(generation: int, process: subprocess.Popen[str]) -> None:
    should_stop = False
    with single_node_test_lock:
        if generation == single_node_test_generation:
            single_node_test_processes.add(process)
        else:
            should_stop = True
    if should_stop:
        _terminate_processes([process])


def unregister_single_node_test_process(generation: int, process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    with single_node_test_lock:
        if generation == single_node_test_generation:
            single_node_test_processes.discard(process)


def single_node_test_is_current(generation: int, cancel_event: threading.Event) -> bool:
    with single_node_test_lock:
        return generation == single_node_test_generation and single_node_test_cancel_event is cancel_event


def finish_single_node_test(generation: int, cancel_event: threading.Event) -> None:
    global single_node_test_cancel_event, single_node_test_processes
    with single_node_test_lock:
        if generation == single_node_test_generation and single_node_test_cancel_event is cancel_event:
            single_node_test_cancel_event = None
            single_node_test_processes = set()


LATENCY_TEST_URL = "https://www.google.com/generate_204"
LATENCY_SOURCE = "google_generate_204"
LATENCY_HTTP_TIMEOUT_SECONDS = 5
LATENCY_DOH_URLS = (
    "https://1.1.1.1/dns-query?name=www.google.com&type=A",
    "https://8.8.8.8/resolve?name=www.google.com&type=A",
)
latency_dns_cache: dict[str, Any] = {"ips": [], "expires_at": 0.0}


def cleanup_test_policy_routing(interface: str, table: int) -> None:
    setup_priority = 21000 + (table - 1000)
    cleanup_policy_routing(interface, table, setup_priority)


def setup_test_policy_routing(interface: str, table: int) -> None:
    setup_priority = 21000 + (table - 1000)
    setup_policy_routing(interface, table, setup_priority)


def _parse_latency_curl_result(result: subprocess.CompletedProcess[str]) -> tuple[bool, int, str]:
    try:
        output = result.stdout.strip().split()
    except Exception:
        output = []
    if result.returncode != 0 or len(output) != 2:
        error = result.stderr.strip() or result.stdout.strip() or "请求失败"
        return False, 0, f"Google 204 延时测试失败: {error}"
    try:
        elapsed_ms = max(1, round(float(output[0]) * 1000))
    except (TypeError, ValueError):
        return False, 0, f"Google 204 返回了无效耗时: {result.stdout.strip()}"
    if output[1] != "204":
        return False, 0, f"Google 204 返回异常状态码: {output[1]}"
    return True, elapsed_ms, f"通过 VPN 请求 Google 204 成功，真实延时 {elapsed_ms} ms"


def resolve_latency_test_ips() -> list[str]:
    now = time.time()
    with APP.lock:
        cached = list(latency_dns_cache.get("ips") or [])
        if cached and float(latency_dns_cache.get("expires_at") or 0) > now:
            return cached
    last_error = ""
    for url in LATENCY_DOH_URLS:
        try:
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "DockerVPNGate/1.0"},
            )
            with urllib.request.urlopen(request, timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
            ips: list[str] = []
            for answer in payload.get("Answer", []):
                value = str(answer.get("data") or "").strip()
                try:
                    socket.inet_aton(value)
                except OSError:
                    continue
                if value not in ips:
                    ips.append(value)
            if ips:
                with APP.lock:
                    latency_dns_cache["ips"] = ips
                    latency_dns_cache["expires_at"] = now + 10 * 60
                return ips
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(f"无法通过可信 DoH 解析 Google 测试地址: {last_error or '无可用 A 记录'}")


def _latency_http_timeout_args(timeout: int) -> tuple[str, str, int]:
    max_time = max(1, int(timeout or LATENCY_HTTP_TIMEOUT_SECONDS))
    connect_timeout = min(LATENCY_HTTP_TIMEOUT_SECONDS, max_time)
    return str(connect_timeout), str(max_time), max_time + 2


def measure_tunnel_http_latency(interface: str, timeout: int = LATENCY_HTTP_TIMEOUT_SECONDS) -> tuple[bool, int, str]:
    try:
        target_ip = resolve_latency_test_ips()[0]
    except Exception as exc:
        return False, 0, str(exc)
    connect_timeout, max_time, process_timeout = _latency_http_timeout_args(timeout)
    command = [
        "curl", "-4", "-sS", "-o", "/dev/null",
        "-w", "%{time_total} %{http_code}",
        "--interface", interface,
        "--resolve", f"www.google.com:443:{target_ip}",
        "--connect-timeout", connect_timeout,
        "--max-time", max_time,
        LATENCY_TEST_URL,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=process_timeout)
    except Exception as exc:
        return False, 0, f"Google 204 延时测试异常: {exc}"
    return _parse_latency_curl_result(result)


def measure_proxy_http_latency(index: int, timeout: int = LATENCY_HTTP_TIMEOUT_SECONDS) -> tuple[bool, int, str]:
    try:
        target_ip = resolve_latency_test_ips()[0]
    except Exception as exc:
        return False, 0, str(exc)
    connect_timeout, max_time, process_timeout = _latency_http_timeout_args(timeout)
    command = [
        "curl", "-4", "-sS", "-o", "/dev/null",
        "-w", "%{time_total} %{http_code}",
        "-x", f"socks5://127.0.0.1:{PROXY_PORTS[index]}",
        "--resolve", f"www.google.com:443:{target_ip}",
        "--connect-timeout", connect_timeout,
        "--max-time", max_time,
        LATENCY_TEST_URL,
    ]
    username, password = proxy_server.get_proxy_credentials()
    if username is not None and password is not None:
        command.extend(["--proxy-user", f"{username}:{password}"])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=process_timeout)
    except Exception as exc:
        return False, 0, f"Google 204 延时测试异常: {exc}"
    return _parse_latency_curl_result(result)


def validate_node_tunnel_latency(
    config_file: str,
    tun_index: int,
    cancel_event: threading.Event | None = None,
    on_process_start: Any = None,
    on_process_end: Any = None,
) -> tuple[bool, int, str]:
    interface = f"tun{tun_index}"
    table = 1000 + tun_index
    process: subprocess.Popen[str] | None = None
    try:
        ok, message, process = run_openvpn_until_ready(
            config_file,
            keep_alive=True,
            route_nopull=True,
            timeout=min(OPENVPN_TEST_TIMEOUT_SECONDS, 15),
            dev=interface,
            log_live=False,
            cancel_event=cancel_event,
            on_process_start=on_process_start,
        )
        if cancel_event is not None and cancel_event.is_set():
            return False, 0, "节点测试已取消"
        if not ok or process is None:
            return False, 0, message
        setup_test_policy_routing(interface, table)
        if cancel_event is not None and cancel_event.is_set():
            return False, 0, "节点测试已取消"
        return measure_tunnel_http_latency(interface)
    except subprocess.CalledProcessError as exc:
        error = (exc.stderr or exc.stdout or str(exc)).strip()
        return False, 0, f"测试隧道策略路由配置失败: {error}"
    except Exception as exc:
        return False, 0, f"测试隧道异常: {exc}"
    finally:
        cleanup_test_policy_routing(interface, table)
        stop_process(process)
        if on_process_end is not None:
            on_process_end(process)


def migrate_legacy_node_latencies() -> int:
    nodes = read_nodes()
    changed = 0
    for node in nodes:
        if node.get("latency_source") == LATENCY_SOURCE:
            continue
        node_changed = False
        if parse_int(node.get("latency_ms")):
            node["latency_ms"] = 0
            node_changed = True
        node["latency_source"] = ""
        if node.get("probe_status") == NODE_STATUS_AVAILABLE:
            node["probe_status"] = NODE_STATUS_QUEUED
            node["probe_message"] = "已加入检测队列，等待通过 VPN 隧道请求 Google 204 重新测量真实延时"
            node_changed = True
        if node_changed:
            changed += 1
    if changed:
        write_json(NODES_FILE, sort_all_nodes(nodes))
    return changed


def test_node_by_id(node_id: str) -> dict[str, Any]:
    generation, cancel_event = begin_single_node_test()
    try:
        with APP.lock:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == node_id), None)
            if not node:
                raise ValueError(f"Node not found: {node_id}")
            config_text = node.get("config_text") or ""
            h = str(node.get("remote_host") or node.get("ip"))
            p = parse_int(node.get("remote_port"))

        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write temp config file: {e}")

        if cancel_event.is_set() or not single_node_test_is_current(generation, cancel_event):
            raise NodeTestCancelled("本次单节点检测已被新的检测请求取代")

        idx = None
        try:
            idx = get_free_test_index()
            ok, latency, message = validate_node_tunnel_latency(
                str(temp_path),
                idx,
                cancel_event,
                on_process_start=lambda process: register_single_node_test_process(generation, process),
                on_process_end=lambda process: unregister_single_node_test_process(generation, process),
            )
        finally:
            if idx is not None:
                release_test_index(idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass

        if cancel_event.is_set() or not single_node_test_is_current(generation, cancel_event):
            raise NodeTestCancelled("本次单节点检测已被新的检测请求取代")

        temp_node = {
            "id": node_id,
            "ip": h,
            "remote_host": h,
            "remote_port": p,
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        if ok:
            vpn_utils.enrich_ip_info([temp_node])

        if cancel_event.is_set() or not single_node_test_is_current(generation, cancel_event):
            raise NodeTestCancelled("本次单节点检测已被新的检测请求取代")

        with APP.lock:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == node_id), None)
            if node:
                node["latency_ms"] = latency
                node["latency_source"] = LATENCY_SOURCE
                node["probe_status"] = NODE_STATUS_AVAILABLE if ok else NODE_STATUS_UNAVAILABLE
                node["probe_message"] = message
                node["probed_at"] = time.time()
                if ok:
                    node["owner"] = temp_node["owner"]
                    node["asn"] = temp_node["asn"]
                    node["as_name"] = temp_node["as_name"]
                    node["location"] = temp_node["location"]
                    node["ip_type"] = temp_node["ip_type"]
                    node["quality"] = temp_node["quality"]

                sorted_nodes = sort_all_nodes(nodes)
                write_json(NODES_FILE, sorted_nodes)
                res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
                return res
            return {}
    finally:
        finish_single_node_test(generation, cancel_event)

def test_multiple_nodes(node_ids: list[str], worker_count: int | None = None) -> list[dict[str, Any]]:
    try:
        requested_workers = int(worker_count if worker_count is not None else NODE_TEST_WORKERS)
    except (TypeError, ValueError):
        requested_workers = NODE_TEST_WORKERS
    worker_count = max(MIN_NODE_TEST_WORKERS, min(MAX_NODE_TEST_WORKERS, requested_workers))
    selected_ids = {str(node_id) for node_id in node_ids if node_id}
    with APP.lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if str(n.get("id") or "") in selected_ids]
        for n in nodes:
            if str(n.get("id") or "") in selected_ids:
                n["probe_status"] = NODE_STATUS_QUEUED
                n["probe_message"] = f"已加入检测队列，等待 {worker_count} 线程工作器处理"
        write_json(NODES_FILE, sort_all_nodes(nodes))

    pending: queue.Queue[dict[str, Any]] = queue.Queue()
    for node in to_test:
        pending.put(node)
    cancel_event = threading.Event()
    with APP.node_test_state_lock:
        if APP.node_test_batch_active:
            raise RuntimeError("节点测试队列已经在运行")
        APP.node_test_batch_active = True
        APP.node_test_cancel_event = cancel_event
        APP.node_test_pending_queue = pending
    clear_batch_probe_statuses()
    for node_id in selected_ids:
        set_batch_probe_status(node_id, NODE_STATUS_QUEUED)

    def test_one(n_info: dict[str, Any]) -> dict[str, Any] | None:
        if cancel_event.is_set():
            return None
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))

        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": NODE_STATUS_UNAVAILABLE,
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }

        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            ok, latency, message = validate_node_tunnel_latency(
                str(temp_path),
                tun_idx,
                cancel_event,
                on_process_start=register_node_test_process,
                on_process_end=unregister_node_test_process,
            )
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
        if cancel_event.is_set():
            return None
        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "latency_source": LATENCY_SOURCE,
            "probe_status": NODE_STATUS_AVAILABLE if ok else NODE_STATUS_UNAVAILABLE,
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        return temp_node

    updated_nodes_map: dict[str, dict[str, Any]] = {}
    result_lock = threading.Lock()
    progress_lock = threading.Lock()
    persist_lock = threading.Lock()
    completed = 0
    total = len(to_test)
    last_state_update_at = 0.0
    last_persisted_count = 0
    last_persisted_at = time.monotonic()

    def persist_results(force: bool = False, reset_pending: bool = False) -> None:
        """Persist completed probes in batches instead of rewriting nodes.json per node."""
        nonlocal last_persisted_at, last_persisted_count
        if not persist_lock.acquire(blocking=force):
            return
        try:
            with result_lock:
                results = dict(updated_nodes_map)
            result_count = len(results)
            now = time.monotonic()
            if (
                not force
                and result_count - last_persisted_count < NODE_TEST_PERSIST_BATCH_SIZE
                and now - last_persisted_at < NODE_TEST_PERSIST_INTERVAL_SECONDS
            ):
                return
            if not force and result_count == last_persisted_count and not reset_pending:
                return

            with APP.lock:
                current_nodes = read_nodes()
                for node in current_nodes:
                    node_id = str(node.get("id") or "")
                    result = results.get(node_id)
                    if result:
                        node.update(result)
                    elif (
                        reset_pending
                        and node_id in selected_ids
                        and node.get("probe_status")
                        in (NODE_STATUS_QUEUED, NODE_STATUS_TESTING, NODE_STATUS_NOT_CHECKED)
                    ):
                        node["probe_status"] = NODE_STATUS_QUEUED
                        node["probe_message"] = "检测被更新节点操作取消，等待重新入队"
                write_json(NODES_FILE, sort_all_nodes(current_nodes))
            last_persisted_count = result_count
            last_persisted_at = now
        finally:
            persist_lock.release()

    def worker() -> None:
        nonlocal completed, last_state_update_at
        while not cancel_event.is_set():
            try:
                node_info = pending.get_nowait()
            except queue.Empty:
                return
            node_id = str(node_info.get("id") or "")
            result: dict[str, Any] | None = None
            set_batch_probe_status(node_id, NODE_STATUS_TESTING)
            try:
                result = test_one(node_info)
            except Exception as exc:
                if not cancel_event.is_set():
                    result = {
                        "id": node_id,
                        "probe_status": NODE_STATUS_UNAVAILABLE,
                        "probe_message": f"Test exception: {exc}",
                        "latency_ms": 0,
                        "latency_source": LATENCY_SOURCE,
                        "probed_at": time.time(),
                    }
            finally:
                pending.task_done()
            if result is None or cancel_event.is_set():
                continue
            with result_lock:
                updated_nodes_map[node_id] = result
            set_batch_probe_status(node_id, str(result.get("probe_status") or NODE_STATUS_UNAVAILABLE))
            progress_message = ""
            with progress_lock:
                completed += 1
                now = time.monotonic()
                if completed == total or now - last_state_update_at >= 1.0:
                    last_state_update_at = now
                    progress_message = (
                        f"{worker_count} 线程并发检测节点：已完成 {completed}/{total}，"
                        f"队列剩余 {pending.qsize()}"
                    )
            if progress_message:
                APP.set_state(
                    last_check_message=progress_message
                )
            persist_results()

    threads = [
        threading.Thread(target=worker, name=f"node-test-{index + 1}", daemon=True)
        for index in range(min(worker_count, total))
    ]
    try:
        APP.set_state(last_check_message=f"已将 {total} 个节点加入队列，使用 {len(threads)} 个线程并发检测")
        for thread in threads:
            thread.start()
        pending.join()
        for thread in threads:
            thread.join()

        if not cancel_event.is_set():
            successful_nodes = [
                result for result in updated_nodes_map.values()
                if result.get("probe_status") == NODE_STATUS_AVAILABLE
            ]
            if successful_nodes:
                try:
                    vpn_utils.enrich_ip_info(successful_nodes)
                except Exception as exc:
                    print(f"[test_multiple_nodes] 批量富化 IP 失败: {exc}", flush=True)
            persist_results(force=True)
    finally:
        if cancel_event.is_set():
            persist_results(force=True, reset_pending=True)
            APP.set_state(last_check_message="当前测试队列已取消并清空")
        clear_batch_probe_statuses()
        with APP.node_test_state_lock:
            APP.node_test_batch_active = False
            APP.node_test_cancel_event = None
            APP.node_test_pending_queue = None

    if cancel_event.is_set():
        raise NodeTestCancelled("节点测试已被更新操作取消")
    return list(updated_nodes_map.values())
