from __future__ import annotations

import os
import sys
from pathlib import Path


def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value


API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
MIN_SCAN_ROWS = 1
MAX_SCAN_ROWS_LIMIT = 2000
DEFAULT_MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, MIN_SCAN_ROWS, MAX_SCAN_ROWS_LIMIT)
MAX_SCAN_ROWS = DEFAULT_MAX_SCAN_ROWS
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 1)
MANUAL_TEST_NODE_LIMIT = env_int("MANUAL_TEST_NODE_LIMIT", 5, 1, 20)
INITIAL_CONNECT_TEST_LIMIT = env_int("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50)
MIN_NODE_TEST_WORKERS = 1
MAX_NODE_TEST_WORKERS = 8
DEFAULT_NODE_TEST_WORKERS = env_int(
    "NODE_TEST_WORKERS", 8, MIN_NODE_TEST_WORKERS, MAX_NODE_TEST_WORKERS
)
NODE_TEST_WORKERS = DEFAULT_NODE_TEST_WORKERS
NODE_TEST_PERSIST_BATCH_SIZE = env_int("NODE_TEST_PERSIST_BATCH_SIZE", 16, 1, 100)
NODE_TEST_PERSIST_INTERVAL_SECONDS = env_int("NODE_TEST_PERSIST_INTERVAL_SECONDS", 5, 1, 60)
MIN_NODE_AUTO_RETEST_SECONDS_PER_NODE = 1
MAX_NODE_AUTO_RETEST_SECONDS_PER_NODE = 3600
DEFAULT_NODE_AUTO_RETEST_SECONDS_PER_NODE = env_int(
    "NODE_AUTO_RETEST_SECONDS_PER_NODE",
    10,
    MIN_NODE_AUTO_RETEST_SECONDS_PER_NODE,
    MAX_NODE_AUTO_RETEST_SECONDS_PER_NODE,
)
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
PROXY_PORTS = (7928, 7929, 7930, 7931, 7932)
PROXY_INTERFACES = tuple(f"tun{index}" for index in range(len(PROXY_PORTS)))
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = 8787
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)
DEFAULT_REGION_NODE_LIMIT = 10
MIN_REGION_NODE_LIMIT = 1
MAX_REGION_NODE_LIMIT = 200
# Kept as compatibility aliases for integrations importing the old names.
DEFAULT_NODE_CACHE_SIZE = DEFAULT_REGION_NODE_LIMIT
MIN_NODE_CACHE_SIZE = MIN_REGION_NODE_LIMIT
MAX_NODE_CACHE_SIZE = MAX_REGION_NODE_LIMIT

ROOT_DIR = (
    Path(sys.executable).resolve().parent
    if globals().get("__compiled__") or getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent.parent
)
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
WEB_DIR = ROOT_DIR / "web"
