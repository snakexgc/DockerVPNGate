from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from .config import DATA_DIR

_lock = threading.RLock()
_last_cleanup_time = 0.0


def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with _lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            try:
                file_day = time.mktime(time.strptime(path.stem, "%Y-%m-%d"))
                today = time.mktime(time.strptime(time.strftime("%Y-%m-%d", time.localtime()), "%Y-%m-%d"))
                expired = today - file_day >= three_days
            except (ValueError, OSError):
                expired = now - path.stat().st_mtime > three_days
            if expired:
                with _lock:
                    path.unlink()
                print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
    except Exception as exc:
        print(f"[清理错误] 清理旧日志失败: {exc}", flush=True)


def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        log_file = logs_dir / f"{time.strftime('%Y-%m-%d', time.localtime())}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "epoch": round(time.time(), 3),
            "level": str(level or "INFO").upper(),
            "module": str(module or "System"),
            "thread": threading.current_thread().name,
            "message": str(message),
        }
        with _lock, open(log_file, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as exc:
        print(f"[Log Error] Failed to write JSON log: {exc}", flush=True)


def read_log_entries(limit: int = 500, level: str = "", search: str = "") -> list[dict[str, Any]]:
    """Read recent structured logs safely, newest files last in the response."""
    limit = max(1, min(2000, int(limit)))
    requested_level = str(level or "").upper()
    needle = str(search or "").casefold()
    logs_dir = DATA_DIR / "logs"
    matches: list[dict[str, Any]] = []
    try:
        paths = sorted(logs_dir.glob("*.json"), reverse=True)
        for path in paths:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in reversed(lines):
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(entry, dict):
                    continue
                if requested_level and str(entry.get("level") or "").upper() != requested_level:
                    continue
                haystack = " ".join(str(entry.get(key) or "") for key in ("module", "thread", "message")).casefold()
                if needle and needle not in haystack:
                    continue
                matches.append(entry)
                if len(matches) >= limit:
                    return list(reversed(matches))
        return list(reversed(matches))
    except OSError:
        return []
