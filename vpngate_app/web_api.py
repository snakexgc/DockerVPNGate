from __future__ import annotations

import json
import re
import threading
import time
import urllib.parse
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from types import ModuleType
from typing import Any

APP: ModuleType
ROUTINE_POLL_ENDPOINTS = ("/api/dashboard", "/api/gateway_status", "/api/traffic", "/api/logs")


def is_routine_successful_poll(command: str, request_path: str, status: Any) -> bool:
    try:
        status_code = int(status)
    except (TypeError, ValueError):
        return False
    path = urllib.parse.urlsplit(request_path).path
    return (
        command == "GET"
        and status_code < 400
        and any(path.endswith(endpoint) for endpoint in ROUTINE_POLL_ENDPOINTS)
    )


def bounded_int_setting(
    payload: dict[str, Any],
    config: dict[str, Any],
    key: str,
    default: int,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    try:
        value = int(payload.get(key, config.get(key, default)))
    except (TypeError, ValueError):
        raise ValueError(f"{label}必须是整数")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label}必须在 {minimum} 到 {maximum} 之间")
    return value


def create_handler(backend: ModuleType) -> type[BaseHTTPRequestHandler]:
    global APP
    APP = backend
    return Handler

class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = APP.load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = APP.load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False

        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()

        session_token = cookies.get("session")
        if not session_token:
            return False

        with APP.lock:
            exp_time = APP.active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == "/":
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            return ""
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        status = args[1] if len(args) > 1 else 0
        if is_routine_successful_poll(self.command, self.path, status):
            return
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = APP.parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "":
            return

        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(APP.LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path in ("/", "/index.html"):
            self.send_bytes(APP.INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/styles.css":
            self.send_bytes(APP.load_web_asset("styles.css").encode("utf-8"), "text/css; charset=utf-8")
        elif effective_path == "/app.js":
            self.send_bytes(APP.load_web_asset("app.js").encode("utf-8"), "text/javascript; charset=utf-8")
        elif effective_path in ("/api/dashboard", "/api/gateway_status"):
            self.send_json({"ok": True, **APP.multi_dashboard_state()})
        elif effective_path == "/api/traffic":
            self.send_json({"ok": True, **APP.traffic_state_payload()})
        elif effective_path == "/api/settings":
            config = APP.load_ui_config()
            region_limit = int(config.get("region_node_limit", APP.DEFAULT_REGION_NODE_LIMIT))
            nodes = APP.read_nodes()
            self.send_json({
                "ok": True,
                "username": config.get("username", ""),
                "secret_path": config.get("secret_path", ""),
                "proxy_username": config.get("proxy_username", ""),
                "proxy_password": config.get("proxy_password", ""),
                "region_node_limit": region_limit,
                "node_test_workers": APP.configured_node_test_workers(config),
                "max_scan_rows": APP.configured_max_scan_rows(config),
                "node_auto_retest_seconds_per_node": APP.configured_node_retest_seconds(config),
                "node_cache_size": region_limit * len(APP.country_choice_payloads(nodes)),
                "node_cache_count": len(nodes),
            })
        elif effective_path == "/api/nodes":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                index = APP.proxy_slot_index((query.get("slot") or ["1"])[0])
                self.send_json({"ok": True, "slot": index + 1, "nodes": APP.public_nodes_for_slot(index)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            node = next((item for item in APP.read_nodes() if Path(item.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/logs":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            level = str((query.get("level") or [""])[0]).upper()
            search = str((query.get("search") or [""])[0]).strip()
            limit = max(1, min(2000, APP.parse_int((query.get("limit") or ["500"])[0]) or 500))
            self.send_json({"ok": True, "logs": APP.read_log_entries(limit=limit, level=level, search=search)})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "":
            return

        if effective_path == "/api/login":
            try:
                payload = self.read_json_body()
                config = APP.load_ui_config()
                if (
                    str(payload.get("username") or "") == config.get("username")
                    and str(payload.get("password") or "") == config.get("password")
                    and config.get("password")
                ):
                    token = uuid.uuid4().hex
                    with APP.lock:
                        APP.active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Set-Cookie", f"session={token}; Path=/{config['secret_path']}/; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_json({"ok": False, "error": "用户名或密码错误"}, HTTPStatus.UNAUTHORIZED)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/logout":
            cookie_header = self.headers.get("Cookie", "")
            token = ""
            for item in cookie_header.split(";"):
                key, separator, value = item.strip().partition("=")
                if separator and key == "session":
                    token = value
                    break
            with APP.lock:
                APP.active_sessions.pop(token, None)
            config = APP.load_ui_config()
            self.send_response(HTTPStatus.OK)
            self.send_header("Set-Cookie", f"session=; Path=/{config['secret_path']}/; HttpOnly; SameSite=Lax; Max-Age=0")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        try:
            if effective_path == "/api/traffic/reset":
                self.read_json_body()
                self.send_json({"ok": True, **APP.reset_traffic_stats()})
                return
            if effective_path == "/api/settings":
                payload = self.read_json_body()
                config = APP.load_ui_config()
                old_username = str(config.get("username") or "")
                old_password = str(config.get("password") or "")
                old_secret_path = str(config.get("secret_path") or "")
                username = str(payload.get("username") or "").strip()
                password = str(payload.get("password") or "")
                password_confirm = str(payload.get("password_confirm") or "")
                current_username = str(payload.get("current_username") or old_username).strip()
                current_password = str(payload.get("current_password") or "")
                secret_path = str(payload.get("secret_path") or "").strip()
                proxy_username = str(payload.get("proxy_username") or "").strip()
                proxy_password = str(payload.get("proxy_password") or "")
                try:
                    region_node_limit = int(payload.get(
                        "region_node_limit",
                        config.get("region_node_limit", APP.DEFAULT_REGION_NODE_LIMIT),
                    ))
                except (TypeError, ValueError):
                    raise ValueError("每地区节点上限必须是整数")
                node_test_workers = bounded_int_setting(
                    payload,
                    config,
                    "node_test_workers",
                    APP.DEFAULT_NODE_TEST_WORKERS,
                    APP.MIN_NODE_TEST_WORKERS,
                    APP.MAX_NODE_TEST_WORKERS,
                    "节点检测并发数",
                )
                max_scan_rows = bounded_int_setting(
                    payload,
                    config,
                    "max_scan_rows",
                    APP.DEFAULT_MAX_SCAN_ROWS,
                    APP.MIN_SCAN_ROWS,
                    APP.MAX_SCAN_ROWS_LIMIT,
                    "API 最大候选数",
                )
                node_retest_seconds = bounded_int_setting(
                    payload,
                    config,
                    "node_auto_retest_seconds_per_node",
                    APP.DEFAULT_NODE_AUTO_RETEST_SECONDS_PER_NODE,
                    APP.MIN_NODE_AUTO_RETEST_SECONDS_PER_NODE,
                    APP.MAX_NODE_AUTO_RETEST_SECONDS_PER_NODE,
                    "每节点自动重测间隔",
                )
                if not username:
                    raise ValueError("管理用户名不能为空")
                if password and password != password_confirm:
                    raise ValueError("两次输入的新密码不一致")
                if password_confirm and not password:
                    raise ValueError("请先填写新密码")
                if password and len(password) < 8:
                    raise ValueError("管理密码至少需要 8 个字符")
                if not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", secret_path):
                    raise ValueError("安全路径只能包含字母、数字、下划线和连字符，长度 6-64")
                admin_auth_changed = username != old_username or bool(password) or secret_path != old_secret_path
                if admin_auth_changed and (
                    current_username != old_username
                    or current_password != old_password
                    or not old_password
                ):
                    raise ValueError("修改用户信息前，请输入正确的原密码")
                if not APP.MIN_REGION_NODE_LIMIT <= region_node_limit <= APP.MAX_REGION_NODE_LIMIT:
                    raise ValueError(
                        f"每地区节点上限必须在 {APP.MIN_REGION_NODE_LIMIT} 到 {APP.MAX_REGION_NODE_LIMIT} 之间"
                    )
                existing_proxy_username = str(config.get("proxy_username") or "")
                existing_proxy_password = str(config.get("proxy_password") or "")
                if proxy_username and not proxy_password:
                    if proxy_username == existing_proxy_username and existing_proxy_password:
                        proxy_password = existing_proxy_password
                    else:
                        raise ValueError("设置新的代理用户名时必须同时填写代理密码")
                if not proxy_username and proxy_password:
                    raise ValueError("代理用户名和密码必须同时填写或同时留空")
                config["username"] = username
                if password:
                    config["password"] = password
                config["secret_path"] = secret_path
                config["proxy_username"] = proxy_username
                config["proxy_password"] = proxy_password
                old_region_node_limit = int(config.get("region_node_limit", APP.DEFAULT_REGION_NODE_LIMIT))
                config["region_node_limit"] = region_node_limit
                config["node_test_workers"] = node_test_workers
                config["max_scan_rows"] = max_scan_rows
                config["node_auto_retest_seconds_per_node"] = node_retest_seconds
                APP.save_ui_config(config)
                if region_node_limit != old_region_node_limit:
                    threading.Thread(
                        target=APP.resize_node_cache_when_idle,
                        args=(region_node_limit,),
                        daemon=True,
                    ).start()
                APP.proxy_server.set_proxy_credentials(proxy_username, proxy_password)
                reauth = username != old_username or (password and password != old_password) or secret_path != old_secret_path
                if reauth:
                    with APP.lock:
                        APP.active_sessions.clear()
                self.send_json({
                    "ok": True,
                    "reauth_required": reauth,
                    "secret_path": secret_path,
                    "region_node_limit": region_node_limit,
                    "node_test_workers": node_test_workers,
                    "max_scan_rows": max_scan_rows,
                    "node_auto_retest_seconds_per_node": node_retest_seconds,
                })

            elif effective_path == "/api/slots/update":
                payload = self.read_json_body()
                index = APP.proxy_slot_index(payload.get("slot"))
                config = APP.load_ui_config()
                slot = config["proxy_slots"][index]
                country = str(payload.get("preferred_country") or "").strip()
                ip_type = str(payload.get("routing_ip_type") or "all").strip()
                switch_mode = str(payload.get("switch_mode") or "auto").strip()
                if ip_type not in ("all", "residential", "hosting"):
                    raise ValueError("无效的 IP 类型")
                if switch_mode not in ("auto", "fixed"):
                    raise ValueError("无效的节点失效策略")
                slot["preferred_country"] = country
                slot["routing_ip_type"] = ip_type
                slot["switch_mode"] = switch_mode
                slot["enabled"] = bool(payload.get("enabled", True))
                APP.save_ui_config(config)
                if not slot["enabled"]:
                    APP.stop_proxy_slot(index, "已在面板中停用")
                else:
                    threading.Thread(target=APP.ensure_proxy_slot, args=(index,), daemon=True).start()
                self.send_json({"ok": True, "slot": APP.proxy_slot_payload(index, APP.read_nodes(), config)})

            elif effective_path == "/api/slots/connect":
                payload = self.read_json_body()
                index = APP.proxy_slot_index(payload.get("slot"))
                message = APP.connect_proxy_slot(index, str(payload.get("node_id") or ""), update_preference=True)
                self.send_json({"ok": True, "message": message})

            elif effective_path == "/api/slots/disconnect":
                payload = self.read_json_body()
                index = APP.proxy_slot_index(payload.get("slot"))
                config = APP.load_ui_config()
                config["proxy_slots"][index]["enabled"] = False
                APP.save_ui_config(config)
                APP.stop_proxy_slot(index, "已手动断开")
                self.send_json({"ok": True})

            elif effective_path == "/api/nodes/refresh":
                if APP.node_refresh_pending.is_set():
                    self.send_json({"ok": True, "running": True, "message": "更新节点任务已经在等待执行"})
                elif APP.node_test_is_active() or APP.node_test_start_pending.is_set():
                    APP.schedule_node_refresh()
                    cancelled = APP.cancel_active_node_tests()
                    self.send_json({
                        "ok": True,
                        "running": True,
                        "preempted": True,
                        "message": (
                            "已清空测试队列并停止当前测试，接下来拉取、合并并重新检测"
                            if cancelled else "已停止等待中的连接测试，接下来更新节点"
                        ),
                    })
                elif APP.maintenance_lock.locked():
                    self.send_json({"ok": True, "running": True, "message": "节点维护正在运行"})
                else:
                    APP.schedule_node_refresh()
                    self.send_json({"ok": True, "running": True, "message": "已开始拉取；新旧节点全量检测后再按地区更新节点池"})

            elif effective_path == "/api/nodes/test-cache":
                if APP.node_test_is_active() or APP.node_test_start_pending.is_set():
                    self.send_json({
                        "ok": True,
                        "running": True,
                        "discarded": True,
                        "message": "连接测试正在运行，全部节点已经入队，本次请求已忽略",
                    })
                elif APP.node_refresh_pending.is_set() or APP.maintenance_lock.locked():
                    self.send_json({
                        "ok": True,
                        "running": True,
                        "discarded": True,
                        "message": "节点更新或维护正在运行，本次连接测试请求已忽略",
                    })
                else:
                    APP.schedule_cached_node_test()
                    worker_count = APP.configured_node_test_workers()
                    self.send_json({
                        "ok": True,
                        "running": True,
                        "message": f"已将缓存池节点加入队列，使用 {worker_count} 线程测试",
                    })

            elif effective_path == "/api/nodes/test":
                payload = self.read_json_body()
                node_id = str(payload.get("node_id") or "").strip()
                if not node_id:
                    raise ValueError("节点 ID 不能为空")
                node = APP.test_node_by_id(node_id)
                self.send_json({"ok": True, "node": node})

            elif effective_path == "/api/slots/test":
                payload = self.read_json_body()
                index = APP.proxy_slot_index(payload.get("slot"))
                result = APP.check_proxy_slot_health(index)
                APP.proxy_slots_runtime[index].update(
                    proxy_ok=bool(result.get("ok")),
                    proxy_ip=result.get("ip", "-") if result.get("ok") else "-",
                    proxy_latency_ms=result.get("latency_ms", 0),
                    error="" if result.get("ok") else str(result.get("error") or "检测失败"),
                )
                self.send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_GATEWAY)

            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except RuntimeError as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.CONFLICT)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
