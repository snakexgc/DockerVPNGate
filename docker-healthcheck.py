#!/usr/bin/env python3
from __future__ import annotations

import socket


with socket.create_connection(("127.0.0.1", 8787), timeout=3):
    pass
