from __future__ import annotations

import re


class UnsafeOpenVPNConfig(ValueError):
    """Raised when a downloaded profile contains directives we do not execute."""


# DockerVPNGate only needs connection and TLS material from VPNGate profiles.
# Everything capable of loading files, starting scripts/plugins, exposing a
# management socket, or changing host networking is intentionally absent.
ALLOWED_DIRECTIVES = frozenset(
    {
        "auth",
        "cipher",
        "client",
        "comp-lzo",
        "compress",
        "connect-retry",
        "connect-retry-max",
        "connect-timeout",
        "data-ciphers",
        "data-ciphers-fallback",
        "dev",
        "dev-type",
        "explicit-exit-notify",
        "float",
        "fragment",
        "hand-window",
        "keepalive",
        "key-direction",
        "mssfix",
        "nobind",
        "peer-fingerprint",
        "persist-key",
        "persist-tun",
        "ping",
        "ping-exit",
        "ping-restart",
        "proto",
        "pull",
        "rcvbuf",
        "remote",
        "remote-cert-tls",
        "reneg-sec",
        "resolv-retry",
        "sndbuf",
        "tls-cipher",
        "tls-ciphersuites",
        "tls-client",
        "tls-version-max",
        "tls-version-min",
        "topology",
        "tun-mtu",
        "verb",
        "verify-x509-name",
    }
)

ALLOWED_INLINE_BLOCKS = frozenset(
    {
        "ca",
        "cert",
        "extra-certs",
        "key",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
    }
)

_DIRECTIVE_RE = re.compile(r"^-{0,2}([A-Za-z0-9_-]+)(?:\s|$)")
_INLINE_TAG_RE = re.compile(r"^<(/?)([A-Za-z0-9_-]+)>$")


def validate_openvpn_config(config_text: str) -> None:
    """Reject profiles outside the small client/TLS directive allowlist."""
    if not isinstance(config_text, str) or not config_text.strip():
        raise UnsafeOpenVPNConfig("OpenVPN 配置为空")

    open_block = ""
    seen_remote = False
    for line_number, raw_line in enumerate(config_text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue

        tag_match = _INLINE_TAG_RE.fullmatch(line)
        if open_block:
            if tag_match and tag_match.group(1) == "/":
                closing = tag_match.group(2).lower()
                if closing != open_block:
                    raise UnsafeOpenVPNConfig(
                        f"OpenVPN 配置第 {line_number} 行关闭了错误的内联块: {closing}"
                    )
                open_block = ""
            continue

        if tag_match:
            closing, block = tag_match.groups()
            block = block.lower()
            if closing:
                raise UnsafeOpenVPNConfig(
                    f"OpenVPN 配置第 {line_number} 行存在多余的结束标签: {block}"
                )
            if block not in ALLOWED_INLINE_BLOCKS:
                raise UnsafeOpenVPNConfig(
                    f"OpenVPN 配置包含不允许的内联块: {block}"
                )
            open_block = block
            continue

        directive_match = _DIRECTIVE_RE.match(line)
        if not directive_match:
            raise UnsafeOpenVPNConfig(
                f"OpenVPN 配置第 {line_number} 行无法安全解析"
            )
        directive = directive_match.group(1).lower()
        if directive not in ALLOWED_DIRECTIVES:
            raise UnsafeOpenVPNConfig(
                f"OpenVPN 配置包含不允许的指令: {directive}"
            )
        if directive == "remote":
            seen_remote = True

    if open_block:
        raise UnsafeOpenVPNConfig(f"OpenVPN 配置的内联块未关闭: {open_block}")
    if not seen_remote:
        raise UnsafeOpenVPNConfig("OpenVPN 配置缺少 remote 指令")
