#!/usr/bin/env python3
from __future__ import annotations
import base64
import os
import secrets
import select
import socket
import ssl
import threading
import urllib.parse
import time
from typing import Any

DOH_RESOLVERS = (
    ("https://dns.cloudflare.com/dns-query", "1.1.1.1"),
    ("https://dns.google/dns-query", "8.8.8.8"),
    ("https://dns.alidns.com/dns-query", "223.5.5.5"),
)
PLAIN_DNS_RESOLVERS = ("1.1.1.1", "8.8.8.8", "223.5.5.5")
DNS_QUERY_TIMEOUT_SECONDS = 2.0
DNS_CACHE_TTL_SECONDS = 60.0
DNS_CACHE_MAX_ENTRIES = 1024
dns_cache_lock = threading.RLock()
dns_cache: dict[tuple[str, str], tuple[float, str]] = {}

def parse_positive_int(value: str | None, default: int) -> int:
    try:
        return max(1, int(value or default))
    except (TypeError, ValueError):
        return default

MAX_PROXY_CONNECTIONS = parse_positive_int(os.environ.get("LOCAL_PROXY_MAX_CONNECTIONS"), 256)
proxy_connection_sem = threading.BoundedSemaphore(MAX_PROXY_CONNECTIONS)
credentials_lock = threading.RLock()
configured_proxy_credentials: tuple[str | None, str | None] | None = None

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def parse_host_port(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        host_part, sep, rest = authority.partition("]")
        host = host_part.lstrip("[")
        port = default_port
        if sep and rest.startswith(":"):
            port_text = rest[1:]
            port = parse_int(port_text) or default_port
        return host, port
    if authority.count(":") == 1:
        host, _, port_text = authority.rpartition(":")
        return host, parse_int(port_text) or default_port
    return authority, default_port

def get_proxy_credentials() -> tuple[str | None, str | None]:
    with credentials_lock:
        if configured_proxy_credentials is not None:
            return configured_proxy_credentials
    user = os.environ.get("LOCAL_PROXY_USER") or os.environ.get("LOCAL_PROXY_USERNAME")
    password = os.environ.get("LOCAL_PROXY_PASS") or os.environ.get("LOCAL_PROXY_PASSWORD")
    if user is None and password is None:
        return None, None
    return user or "", password or ""

def set_proxy_credentials(username: str | None, password: str | None) -> None:
    """Update the shared credentials used by every proxy listener."""
    global configured_proxy_credentials
    with credentials_lock:
        if username is None and password is None:
            configured_proxy_credentials = None
        elif not username and not password:
            configured_proxy_credentials = (None, None)
        else:
            configured_proxy_credentials = (username or "", password or "")

def proxy_auth_enabled() -> bool:
    user, password = get_proxy_credentials()
    return user is not None and password is not None

def parse_http_basic_auth(lines: list[str]) -> tuple[str | None, str | None]:
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep or name.strip().lower() != "proxy-authorization":
            continue
        scheme, _, token = value.strip().partition(" ")
        if scheme.lower() != "basic" or not token:
            return None, None
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="replace")
        except Exception:
            return None, None
        username, sep, password = decoded.partition(":")
        if not sep:
            return None, None
        return username, password
    return None, None

def check_credentials(username: str | None, password: str | None) -> bool:
    expected_user, expected_pass = get_proxy_credentials()
    if expected_user is None or expected_pass is None:
        return True
    return secrets.compare_digest(username or "", expected_user) and secrets.compare_digest(password or "", expected_pass)

def build_dns_query(host: str, qtype: int) -> tuple[bytes, bytes] | None:
    labels = []
    try:
        for part in host.rstrip(".").split("."):
            if not part:
                return None
            encoded = part.encode("idna")
            if len(encoded) > 63:
                return None
            labels.append(len(encoded).to_bytes(1, "big") + encoded)
    except (UnicodeError, ValueError):
        return None

    qname = b"".join(labels) + b"\x00"
    if len(qname) > 255:
        return None
    tx_id = secrets.randbits(16).to_bytes(2, "big")
    packet = (
        tx_id
        + b"\x01\x00"  # recursion desired
        + b"\x00\x01"  # one question
        + b"\x00\x00\x00\x00\x00\x00"
        + qname
        + qtype.to_bytes(2, "big")
        + b"\x00\x01"  # IN class
    )
    return tx_id, packet


def parse_dns_answer(response: bytes, tx_id: bytes, qtype: int) -> str | None:
    try:
        if len(response) < 12 or response[:2] != tx_id or not response[2] & 0x80:
            return None
        if response[3] & 0x0F:
            return None

        offset = 12
        questions_count = int.from_bytes(response[4:6], "big")
        for _ in range(questions_count):
            while offset < len(response):
                length = response[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            offset += 4

        answers_count = int.from_bytes(response[6:8], "big")
        for _ in range(answers_count):
            while offset < len(response):
                length = response[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            if offset + 10 > len(response):
                return None
            answer_type = int.from_bytes(response[offset : offset + 2], "big")
            answer_class = int.from_bytes(response[offset + 2 : offset + 4], "big")
            data_length = int.from_bytes(response[offset + 8 : offset + 10], "big")
            offset += 10
            if offset + data_length > len(response):
                return None
            record = response[offset : offset + data_length]
            if answer_type == qtype and answer_class == 1:
                if qtype == 1 and data_length == 4:
                    return socket.inet_ntoa(record)
                if qtype == 28 and data_length == 16:
                    return socket.inet_ntop(socket.AF_INET6, record)
            offset += data_length
    except (IndexError, OSError, ValueError):
        return None
    return None


def bind_socket_to_interface(sock: socket.socket, interface: str) -> bool:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode("utf-8"))
        return True
    except OSError as exc:
        if "operation not permitted" in str(exc).lower() or exc.errno == 1:
            print(f"[DNS 绑定失败] [错误代码 3006] DNS 解析绑定 {interface} 权限不足，请确保程序以 root 权限运行！", flush=True)
        elif "no such device" in str(exc).lower() or exc.errno == 19:
            print(f"[DNS 绑定失败] [错误代码 3004] DNS 解析绑定 {interface} 失败，网卡设备不存在，请检查 VPN 连接！", flush=True)
        return False


def decode_chunked_body(body: bytes) -> bytes | None:
    decoded = bytearray()
    offset = 0
    try:
        while True:
            line_end = body.index(b"\r\n", offset)
            size_text = body[offset:line_end].split(b";", 1)[0]
            size = int(size_text, 16)
            offset = line_end + 2
            if size == 0:
                return bytes(decoded)
            chunk_end = offset + size
            if chunk_end + 2 > len(body) or body[chunk_end : chunk_end + 2] != b"\r\n":
                return None
            decoded.extend(body[offset:chunk_end])
            offset = chunk_end + 2
    except (ValueError, IndexError):
        return None


def parse_doh_http_response(response: bytes) -> bytes | None:
    headers_raw, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        return None
    header_lines = headers_raw.split(b"\r\n")
    status_parts = header_lines[0].split(b" ", 2)
    if len(status_parts) < 2 or status_parts[1] != b"200":
        return None
    headers: dict[bytes, bytes] = {}
    for line in header_lines[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            headers[name.strip().lower()] = value.strip().lower()
    if b"chunked" in headers.get(b"transfer-encoding", b""):
        return decode_chunked_body(body)
    content_length = headers.get(b"content-length")
    if content_length is not None:
        try:
            expected = int(content_length)
        except ValueError:
            return None
        if len(body) < expected:
            return None
        return body[:expected]
    return body


def doh_query_over_interface(
    host: str,
    qtype: int,
    endpoint: str,
    bootstrap_ip: str,
    timeout: float,
    interface: str | None,
) -> str | None:
    query = build_dns_query(host, qtype)
    if query is None:
        return None
    tx_id, packet = query
    parsed_endpoint = urllib.parse.urlsplit(endpoint)
    if parsed_endpoint.scheme != "https" or not parsed_endpoint.hostname:
        return None
    path = parsed_endpoint.path or "/dns-query"
    if parsed_endpoint.query:
        path += f"?{parsed_endpoint.query}"

    raw_sock = None
    tls_sock = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        if interface is not None and not bind_socket_to_interface(raw_sock, interface):
            return None
        raw_sock.connect((bootstrap_ip, parsed_endpoint.port or 443))
        tls_sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=parsed_endpoint.hostname)
        raw_sock = None
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {parsed_endpoint.hostname}\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Type: application/dns-message\r\n"
            f"Content-Length: {len(packet)}\r\n"
            "User-Agent: DockerVPNGate/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + packet
        tls_sock.sendall(request)
        chunks = []
        total = 0
        while total <= 65536:
            chunk = tls_sock.recv(min(16384, 65537 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > 65536:
            return None
        dns_response = parse_doh_http_response(b"".join(chunks))
        if dns_response is None:
            return None
        return parse_dns_answer(dns_response, tx_id, qtype)
    except (OSError, ssl.SSLError, ValueError):
        return None
    finally:
        for sock in (tls_sock, raw_sock):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


def dns_query_over_interface(host: str, qtype: int, dns_server: str, timeout: float, interface: str) -> str | None:
    query = build_dns_query(host, qtype)
    if query is None:
        return None
    tx_id, packet = query
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        if not bind_socket_to_interface(sock, interface):
            return None
        sock.sendto(packet, (dns_server, 53))
        response, _ = sock.recvfrom(4096)
        return parse_dns_answer(response, tx_id, qtype)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def resolve_dns_over_interface(host: str, interface: str, timeout: float = DNS_QUERY_TIMEOUT_SECONDS) -> str | None:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass

    cache_key = (interface, host.rstrip(".").lower())
    now = time.monotonic()
    with dns_cache_lock:
        cached = dns_cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]
        dns_cache.pop(cache_key, None)

    resolved_ip = None
    for endpoint, bootstrap_ip in DOH_RESOLVERS:
        for qtype in (1, 28):
            resolved_ip = doh_query_over_interface(host, qtype, endpoint, bootstrap_ip, timeout, interface)
            if resolved_ip:
                break
        if resolved_ip:
            break

    if not resolved_ip:
        for dns_server in PLAIN_DNS_RESOLVERS:
            for qtype in (1, 28):
                resolved_ip = dns_query_over_interface(host, qtype, dns_server, timeout, interface)
                if resolved_ip:
                    break
            if resolved_ip:
                break

    if resolved_ip:
        with dns_cache_lock:
            completion_time = time.monotonic()
            expired_keys = [key for key, value in dns_cache.items() if value[0] <= completion_time]
            for key in expired_keys:
                dns_cache.pop(key, None)
            while len(dns_cache) >= DNS_CACHE_MAX_ENTRIES:
                dns_cache.pop(next(iter(dns_cache)))
            dns_cache[cache_key] = (completion_time + DNS_CACHE_TTL_SECONDS, resolved_ip)
    return resolved_ip

def create_connection(address: tuple[str, int], interface: str, timeout: float = 20) -> socket.socket:
    host, port = address
    resolved_ip = resolve_dns_over_interface(host, interface)
    if not resolved_ip:
        raise OSError(
            f"[错误代码 3011] [ERR_TUN_DNS_FAILED] 无法通过 {interface} 解析目标域名 {host}；"
            "为防止 DNS 从物理网络泄漏，已拒绝回退到系统解析器。"
        )

    try:
        socket.inet_pton(socket.AF_INET, resolved_ip)
        af = socket.AF_INET
        socket_address: tuple[Any, ...] = (resolved_ip, port)
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, resolved_ip)
        except OSError as exc:
            raise OSError(f"隧道 DNS 返回了无效地址: {resolved_ip}") from exc
        af = socket.AF_INET6
        socket_address = (resolved_ip, port, 0, 0)

    sock = socket.socket(af, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode("utf-8"))
        sock.connect(socket_address)
        return sock
    except OSError as exc:
        if "operation not permitted" in str(exc).lower() or exc.errno == 1:
            exc = OSError(f"[错误代码 3006] [ERR_PROXY_BIND_TUN_PERM_DENIED] 绑定虚拟网卡 {interface} 失败，权限不足！必须以 root 权限运行，或者进程缺少 CAP_NET_RAW 权限。")
        elif "no such device" in str(exc).lower() or exc.errno == 19:
            exc = OSError(f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] 绑定虚拟网卡 {interface} 失败，找不到设备！这通常是因为 OpenVPN 核心未能成功连接或已被异常终止。")
        sock.close()
        raise exc

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored or not readable:
            return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data:
                return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes, interface: str) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        if proxy_auth_enabled():
            if 2 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            auth_version = recv_exact(client, 1)[0]
            if auth_version != 1:
                client.sendall(b"\x01\x01")
                return
            username = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            password = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            if not check_credentials(username, password):
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
        else:
            client.sendall(b"\x05\x00")
        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if address_type == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = int.from_bytes(recv_exact(client, 2), "big")
        try:
            upstream = create_connection((host, port), interface, timeout=20)
        except Exception as e:
            print(f"[SOCKS5 代理失败] 目标 {host}:{port} 连接失败: {e}", flush=True)
            try:
                client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            raise
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(client, upstream)
    finally:
        client.close()
        if upstream:
            upstream.close()

def read_http_header(client: socket.socket, first_byte: bytes) -> bytes:
    data = first_byte
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def http_client(client: socket.socket, first_byte: bytes, interface: str) -> None:
    upstream = None
    try:
        header = read_http_header(client, first_byte)
        if b"\r\n\r\n" not in header:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        head, rest = header.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if not version.startswith("HTTP/"):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if proxy_auth_enabled():
            username, password = parse_http_basic_auth(lines[1:])
            if not check_credentials(username, password):
                client.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"DockerVPNGate Proxy\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                return
        if method.upper() == "CONNECT":
            host, port = parse_host_port(target, 443)
            upstream = create_connection((host, port), interface, timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            relay(client, upstream)
            return

        try:
            parsed = urllib.parse.urlsplit(target)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        hostname = parsed.hostname
        port = parsed.port
        scheme = parsed.scheme
        if not hostname:
            # Fallback to Host header
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host_val = line.split(":", 1)[1].strip()
                    if "[" in host_val and "]" in host_val:
                        host_part, _, port_part = host_val.rpartition("]")
                        hostname = host_part.lstrip("[")
                        if port_part.startswith(":"):
                            p_val = port_part.lstrip(":")
                            port = int(p_val) if p_val.isdigit() else None
                        else:
                            port = None
                    else:
                        hostname, parsed_port = parse_host_port(host_val, 0)
                        port = parsed_port or None
                    break
        if not hostname:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        port = port or (443 if scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        upstream = create_connection((hostname, port), interface, timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except Exception as e:
        print(f"[HTTP 代理失败] 代理请求目标连接失败: {e}", flush=True)
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
    finally:
        client.close()
        if upstream:
            upstream.close()

def proxy_client(client: socket.socket, address: tuple[Any, ...], interface: str) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\x05":
            socks5_client(client, first, interface)
        else:
            http_client(client, first, interface)
    except Exception as e:
        err_msg = str(e)
        if "[错误代码" in err_msg:
            print(f"[代理客户端连接失败] 客户端 {address} 遭遇系统性阻碍: {err_msg}", flush=True)
        try:
            client.close()
        except OSError:
            pass

def start_proxy_server(host: str, port: int, interface: str = "tun0") -> None:
    is_ipv6 = ":" in host or host == ""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    server = None
    try:
        server = socket.socket(af, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if is_ipv6:
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        server.bind((host, port))
        server.listen(256)
        print(f"HTTP/SOCKS5 proxy listening on {host}:{port} via {interface}", flush=True)
    except Exception as e:
        if server is not None:
            try:
                server.close()
            except Exception:
                pass
        if is_ipv6 and host in ("::", ""):
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 0.0.0.0 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("0.0.0.0", port))
                server.listen(256)
                print(f"HTTP/SOCKS5 proxy listening on 0.0.0.0:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="0.0.0.0")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 0.0.0.0:{port}: {diag_msg}", flush=True)
                return
        elif is_ipv6 and host == "::1":
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 127.0.0.1 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", port))
                server.listen(256)
                print(f"HTTP/SOCKS5 proxy listening on 127.0.0.1:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="127.0.0.1")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 127.0.0.1:{port}: {diag_msg}", flush=True)
                return
        else:
            import vpn_utils
            diag = vpn_utils.diagnose_local_obstructions(port, host=host)
            diag_msg = diag[1] if diag else str(e)
            print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on {host}:{port}: {diag_msg}", flush=True)
            return

    while True:
        try:
            client, address = server.accept()
            if not proxy_connection_sem.acquire(blocking=False):
                print(f"[代理限流] 当前连接数已达到上限 {MAX_PROXY_CONNECTIONS}，拒绝客户端 {address}", flush=True)
                try:
                    client.close()
                except OSError:
                    pass
                continue

            def run_client(
                accepted_client: socket.socket = client,
                accepted_address: tuple[Any, ...] = address,
            ) -> None:
                try:
                    proxy_client(accepted_client, accepted_address, interface)
                finally:
                    proxy_connection_sem.release()

            threading.Thread(target=run_client, daemon=True).start()
        except Exception as e:
            print(f"[ERROR] Proxy accept failed: {e}", flush=True)
            time.sleep(0.5)
