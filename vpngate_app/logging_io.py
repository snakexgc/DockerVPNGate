from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any


class Tee:
    def __init__(self, file_path: str, max_bytes: int = 10 * 1024 * 1024):
        self.path = Path(file_path)
        self.max_bytes = max(1024, int(max_bytes))
        self.path.parent.mkdir(exist_ok=True, parents=True)
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                backup = self.path.with_suffix(self.path.suffix + ".1")
                if backup.exists():
                    backup.unlink()
                self.path.replace(backup)
        except OSError:
            pass
        self.file = open(self.path, "a", encoding="utf-8")
        self.stdout = sys.stdout
        self._lock = threading.RLock()
        self._buffer = ""
        self._emitting = threading.local()

    def _rotate_for_write(self, data: str) -> None:
        try:
            current_size = self.path.stat().st_size if self.path.exists() else 0
            incoming_size = len(data.encode("utf-8"))
            if current_size + incoming_size < self.max_bytes:
                return
            self.file.flush()
            self.file.close()
            backup = self.path.with_suffix(self.path.suffix + ".1")
            if backup.exists():
                backup.unlink()
            if self.path.exists():
                self.path.replace(backup)
            self.file = open(self.path, "a", encoding="utf-8")
        except OSError:
            if self.file.closed:
                self.file = open(self.path, "a", encoding="utf-8")

    @staticmethod
    def _classify(line: str) -> tuple[str, str]:
        lowered = line.casefold()
        level = "ERROR" if any(value in lowered for value in ("[error", "[错误", "traceback", "异常:")) else (
            "WARNING" if any(value in lowered for value in ("[warn", "[警告", "失败", "超时")) else "INFO"
        )
        module = "Console"
        if line.startswith("[") and "]" in line:
            module = line[1:line.index("]")][:48] or module
        return level, module

    def _emit_structured(self, line: str) -> None:
        if not line.strip() or getattr(self._emitting, "active", False):
            return
        self._emitting.active = True
        try:
            from .logging_utils import log_to_json
            level, module = self._classify(line)
            log_to_json(level, module, line.strip())
        finally:
            self._emitting.active = False

    def write(self, data: str) -> None:
        with self._lock:
            self.stdout.write(data)
            self._rotate_for_write(data)
            self.file.write(data)
            self.file.flush()
            self._buffer += data
            while "\n" in self._buffer:
                line, self._buffer = self._buffer.split("\n", 1)
                self._emit_structured(line.rstrip("\r"))

    def flush(self) -> None:
        with self._lock:
            self.stdout.flush()
            self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)
