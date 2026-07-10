from __future__ import annotations

import subprocess
import threading


_routing_lock = threading.RLock()


def _delete_all_rules(command: list[str]) -> None:
    """Delete every duplicate of an application-owned policy rule."""
    for _ in range(32):
        try:
            result = subprocess.run(command, capture_output=True, timeout=2)
        except Exception:
            return
        if result.returncode != 0:
            return


def cleanup_policy_routing(interface: str, table: int, priority: int) -> None:
    """Remove policy routing even when the referenced TUN device is already gone."""
    with _routing_lock:
        # New rules use a stable priority, so they can be removed after OpenVPN
        # has already destroyed the TUN interface.
        _delete_all_rules(["ip", "rule", "del", "priority", str(priority)])

        # Also clean rules created by older releases. This form requires the
        # device to still exist, but is useful during an in-place reconnect.
        _delete_all_rules(
            ["ip", "rule", "del", "oif", interface, "table", str(table)]
        )
        try:
            subprocess.run(
                ["ip", "route", "flush", "table", str(table)],
                capture_output=True,
                timeout=2,
            )
        except Exception:
            pass


def setup_policy_routing(interface: str, table: int, priority: int) -> None:
    """Route only sockets explicitly bound to interface through its VPN table."""
    with _routing_lock:
        cleanup_policy_routing(interface, table, priority)
        try:
            subprocess.run(
                ["ip", "route", "add", "default", "dev", interface, "table", str(table)],
                check=True,
                capture_output=True,
                text=True,
                timeout=3,
            )
            subprocess.run(
                [
                    "ip", "rule", "add", "priority", str(priority),
                    "oif", interface, "table", str(table),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=3,
            )
        except Exception:
            cleanup_policy_routing(interface, table, priority)
            raise

        for target in ("all", "default", interface):
            try:
                subprocess.run(
                    ["sysctl", "-w", f"net.ipv4.conf.{target}.rp_filter=2"],
                    capture_output=True,
                    timeout=2,
                )
            except Exception:
                pass
