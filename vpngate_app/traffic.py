from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class TrafficMonitor:
    """In-memory TUN traffic accounting; process restart intentionally clears data."""

    def __init__(self, interfaces: tuple[str, ...]) -> None:
        self.interfaces = interfaces
        try:
            self.timezone = ZoneInfo(os.environ.get("TRAFFIC_TIMEZONE", "Asia/Shanghai"))
        except (ZoneInfoNotFoundError, ValueError):
            self.timezone = timezone(timedelta(hours=8), name="Asia/Shanghai")
        self.lock = threading.Lock()
        self.slots = [self._new_slot() for _ in interfaces]

    @staticmethod
    def _new_slot() -> dict[str, Any]:
        return {
            "day": "", "last_rx": None, "last_tx": None, "last_sample": 0.0,
            "download_bps": 0, "upload_bps": 0,
            "today_download": 0, "today_upload": 0,
            "total_download": 0, "total_upload": 0,
        }

    def day_key(self) -> str:
        return datetime.now(self.timezone).date().isoformat()

    @staticmethod
    def read_counter(interface: str, counter: str) -> int | None:
        try:
            path = Path("/sys/class/net") / interface / "statistics" / counter
            return int(path.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return None

    def sample_slot(self, index: int) -> None:
        now, day = time.monotonic(), self.day_key()
        with self.lock:
            rx = self.read_counter(self.interfaces[index], "rx_bytes")
            tx = self.read_counter(self.interfaces[index], "tx_bytes")
            state = self.slots[index]
            if state["day"] != day:
                state.update(day=day, today_download=0, today_upload=0)
            elapsed = now - float(state["last_sample"] or 0)
            last_rx, last_tx = state["last_rx"], state["last_tx"]
            if rx is None or tx is None:
                state.update(last_rx=None, last_tx=None, download_bps=0, upload_bps=0)
            else:
                down = rx - int(last_rx) if last_rx is not None and rx >= int(last_rx) else 0
                up = tx - int(last_tx) if last_tx is not None and tx >= int(last_tx) else 0
                state.update(last_rx=rx, last_tx=tx)
                state["today_download"] += down; state["today_upload"] += up
                state["total_download"] += down; state["total_upload"] += up
                if elapsed > 0 and last_rx is not None and last_tx is not None:
                    state["download_bps"], state["upload_bps"] = int(down / elapsed), int(up / elapsed)
                else:
                    state["download_bps"], state["upload_bps"] = 0, 0
            state["last_sample"] = now

    def reset(self) -> dict[str, Any]:
        now, day = time.monotonic(), self.day_key()
        with self.lock:
            for index, interface in enumerate(self.interfaces):
                self.slots[index].update(
                    day=day, last_rx=self.read_counter(interface, "rx_bytes"),
                    last_tx=self.read_counter(interface, "tx_bytes"), last_sample=now,
                    download_bps=0, upload_bps=0, today_download=0, today_upload=0,
                    total_download=0, total_upload=0,
                )
        return self.snapshot()

    def slot_payload(self, index: int) -> dict[str, int]:
        with self.lock:
            state = self.slots[index]
            return {
                "download_bps": int(state["download_bps"]), "upload_bps": int(state["upload_bps"]),
                "today_download": int(state["today_download"]), "today_upload": int(state["today_upload"]),
                "today_total": int(state["today_download"] + state["today_upload"]),
                "total_download": int(state["total_download"]), "total_upload": int(state["total_upload"]),
                "total": int(state["total_download"] + state["total_upload"]),
            }

    def snapshot(self) -> dict[str, Any]:
        return {
            "sampled_at": time.time(), "day": self.day_key(),
            "slots": [{"id": index + 1, **self.slot_payload(index)} for index in range(len(self.interfaces))],
        }

    def run(self) -> None:
        while True:
            started = time.monotonic()
            for index in range(len(self.interfaces)):
                self.sample_slot(index)
            time.sleep(max(0.1, 1.0 - (time.monotonic() - started)))
