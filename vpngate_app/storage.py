from __future__ import annotations

import json
import os
import random
import string
import threading
from pathlib import Path
from typing import Any

from .config import (
    DATA_DIR, DEFAULT_REGION_NODE_LIMIT, MAX_REGION_NODE_LIMIT, MIN_REGION_NODE_LIMIT,
    NODES_FILE, PROXY_INTERFACES, PROXY_PORTS, UI_HOST, UI_PORT,
)

storage_lock = threading.RLock()


def write_json(path: Path, data: Any) -> None:
    with storage_lock:
        path.parent.mkdir(exist_ok=True, parents=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)


def read_json(path: Path, default: Any) -> Any:
    with storage_lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default


def _random_credential() -> str:
    chars = string.ascii_letters + string.digits
    while True:
        value = "".join(random.choices(chars, k=12))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def generate_random_password() -> str:
    return _random_credential()


def generate_random_username() -> str:
    while True:
        value = _random_credential()
        if value[0].isalpha():
            return value


def default_proxy_slot(index: int) -> dict[str, Any]:
    return {
        "id": index + 1,
        "port": PROXY_PORTS[index],
        "interface": PROXY_INTERFACES[index],
        "preferred_country": "",
        "routing_ip_type": "all",
        "switch_mode": "auto",
        "enabled": True,
        "last_node_id": "",
    }


def normalize_proxy_slots(value: Any, legacy_country: str = "") -> list[dict[str, Any]]:
    source = value if isinstance(value, list) else []
    normalized: list[dict[str, Any]] = []
    for index in range(len(PROXY_PORTS)):
        slot = default_proxy_slot(index)
        if index < len(source) and isinstance(source[index], dict):
            incoming = source[index]
            slot["preferred_country"] = str(incoming.get("preferred_country") or "").strip()
            ip_type = str(incoming.get("routing_ip_type") or "all").strip()
            slot["routing_ip_type"] = ip_type if ip_type in ("all", "residential", "hosting") else "all"
            switch_mode = str(incoming.get("switch_mode") or "auto").strip()
            slot["switch_mode"] = switch_mode if switch_mode in ("auto", "fixed") else "auto"
            slot["enabled"] = bool(incoming.get("enabled", True))
            slot["last_node_id"] = str(incoming.get("last_node_id") or "").strip()
        elif index == 0 and legacy_country:
            slot["preferred_country"] = legacy_country
        normalized.append(slot)
    return normalized


def load_ui_config() -> dict[str, Any]:
    with storage_lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "", "secret_path": "EJsW2EeBo9lY", "password": "",
            "host": UI_HOST, "port": UI_PORT,
            "proxy_username": os.environ.get("LOCAL_PROXY_USER") or os.environ.get("LOCAL_PROXY_USERNAME") or "",
            "proxy_password": os.environ.get("LOCAL_PROXY_PASS") or os.environ.get("LOCAL_PROXY_PASSWORD") or "",
            "region_node_limit": DEFAULT_REGION_NODE_LIMIT,
            "proxy_slots": normalize_proxy_slots(None),
        }
        updated = False
        data: dict[str, Any] = {}
        if auth_file.exists():
            try:
                loaded = json.loads(auth_file.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
                    config.update(data)
            except Exception:
                updated = True
        if not config.get("username"):
            config["username"] = generate_random_username(); updated = True
        if not config.get("password"):
            config["password"] = generate_random_password(); updated = True
        if config.get("port") != UI_PORT:
            config["port"] = UI_PORT; updated = True
        if config.get("host") != UI_HOST:
            config["host"] = UI_HOST; updated = True
        legacy_country = str(data.get("force_country") or "").strip() if data.get("routing_mode") == "fixed_region" else ""
        slot_source = config.get("proxy_slots") if "proxy_slots" in data else None
        normalized_slots = normalize_proxy_slots(slot_source, legacy_country)
        if "proxy_slots" not in data or normalized_slots != config.get("proxy_slots"):
            config["proxy_slots"] = normalized_slots; updated = True
        for key in ("proxy_username", "proxy_password"):
            if key not in data:
                updated = True
            config[key] = str(config.get(key) or "")
        legacy_cache_size = config.pop("node_cache_size", None)
        if legacy_cache_size is not None:
            updated = True
        try:
            region_node_limit = int(config.get("region_node_limit", DEFAULT_REGION_NODE_LIMIT))
        except (TypeError, ValueError):
            region_node_limit = DEFAULT_REGION_NODE_LIMIT
        if not MIN_REGION_NODE_LIMIT <= region_node_limit <= MAX_REGION_NODE_LIMIT:
            region_node_limit = DEFAULT_REGION_NODE_LIMIT
        if config.get("region_node_limit") != region_node_limit:
            config["region_node_limit"] = region_node_limit; updated = True
        for key in ("proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback"):
            if key in config:
                config.pop(key, None); updated = True
        if not auth_file.exists() or updated:
            try:
                write_json(auth_file, config)
            except Exception:
                pass
        return config


def save_ui_config(config: dict[str, Any]) -> None:
    write_json(DATA_DIR / "ui_auth.json", config)


def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(NODES_FILE, [])
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
