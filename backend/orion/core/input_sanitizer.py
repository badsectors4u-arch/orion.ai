"""
Orion Security Platform — Target Input Sanitizer.

PURPOSE: The scanner is the largest attack surface in a SaaS that runs
Nmap and SQLMap. This module is the ONLY gate between user input and
active scanning. Everything here is fail-closed.

SECURITY RULES:
- ALWAYS block cloud metadata IPs (169.254.169.254 etc.) to prevent SSRF.
- Reject non-http(s) schemes (file://, gopher://, dict://, ftp://).
- Reject URLs with embedded credentials (user:pass@host) used to bypass allowlists.
- Resolve DNS and check against private-range blocklists.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlparse, urlunparse

from pydantic import ValidationError

from orion.core.schemas import SanitizedTarget


# ──────────────────────────────────────────────────────────────────────
# Hard-blocked IPs — NEVER allowed, regardless of allow_private
# ──────────────────────────────────────────────────────────────────────
ALWAYS_BLOCKED_IPS: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS / GCP / Azure / OpenStack metadata
    "169.254.170.2",    # AWS ECS task metadata
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",    # AWS IPv6 metadata
})


# ──────────────────────────────────────────────────────────────────────
# Blocked hostname aliases (case-insensitive)
# ──────────────────────────────────────────────────────────────────────
BLOCKED_HOSTNAMES: frozenset[str] = frozenset({
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "instance-data.ec2.internal",
    "kubernetes.default",
    "kubernetes.default.svc",
})


# ──────────────────────────────────────────────────────────────────────
# Private / special-purpose networks — blocked unless allow_private=True
# ──────────────────────────────────────────────────────────────────────
PRIVATE_NETWORKS_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),      # CGN (RFC6598)
    ipaddress.ip_network("127.0.0.0/8"),        # loopback
    ipaddress.ip_network("169.254.0.0/16"),     # link-local
    ipaddress.ip_network("172.16.0.0/12"),      # RFC1918
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),     # RFC1918
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),        # multicast
    ipaddress.ip_network("240.0.0.0/4"),        # reserved
    ipaddress.ip_network("255.255.255.255/32"), # broadcast
)

PRIVATE_NETWORKS_V6: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),            # loopback
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("fc00::/7"),           # ULA
    ipaddress.ip_network("fe80::/10"),          # link-local
    ipaddress.ip_network("ff00::/8"),
)


ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

MAX_TARGET_LENGTH = 2048
MAX_HOSTNAME_LENGTH = 253
DNS_TIMEOUT_SECONDS = 3.0


# ──────────────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────────────
def is_private_ip(ip: str) -> bool:
    """
    Returns True if `ip` is private, loopback, link-local, reserved, or
    otherwise non-routable. Malformed input returns True (fail-closed).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return True  # can't parse → treat as unsafe

    # Fix: Check for IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped

    if str(addr) in ALWAYS_BLOCKED_IPS:
        return True

    networks: Iterable = (
        PRIVATE_NETWORKS_V4 if addr.version == 4 else PRIVATE_NETWORKS_V6
    )
    return any(addr in net for net in networks)



def is_blocked_hostname(hostname: str) -> bool:
    """Returns True if the hostname is a known local/metadata alias."""
    h = hostname.lower().rstrip(".")
    if h in BLOCKED_HOSTNAMES:
        return True
    if h.endswith(".localhost") or h.endswith(".internal"):
        return True
    return False


async def _resolve(hostname: str) -> str:
    """Async DNS resolution with timeout."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP),
            timeout=DNS_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise ValueError(f"DNS timeout resolving '{hostname}'")
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for '{hostname}': {e}")

    if not infos:
        raise ValueError(f"DNS returned no addresses for '{hostname}'")

    v4 = [info[4][0] for info in infos if info[0] == socket.AF_INET]
    if v4:
        return v4[0]
    return infos[0][4][0]


# ──────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────
async def sanitize_target(
    target: str,
    *,
    allow_private: bool = False,
) -> SanitizedTarget:
    """
    Validate and normalize a user-supplied scan target.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target is empty.")

    raw = target.strip()
    if len(raw) > MAX_TARGET_LENGTH:
        raise ValueError(f"Target exceeds {MAX_TARGET_LENGTH} chars.")

    # 1. Ensure a scheme
    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)

    # 2. Scheme allowlist
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme '{scheme}' is not allowed. Use http or https.")

    # 3. Reject credentials in URL
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not allowed.")

    # 4. Hostname validation
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Target has no hostname.")
    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise ValueError("Hostname too long.")

    # 5. IDN → punycode
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        raise ValueError(f"Invalid hostname: '{hostname}'")

    # 6. Block known local/metadata aliases
    if is_blocked_hostname(ascii_hostname):
        raise ValueError(f"Target '{ascii_hostname}' is a protected hostname.")

    # 7. Port validation
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid port in URL.")

    # 8. Resolve DNS and enforce IP-level policy
    try:
        ipaddress.ip_address(ascii_hostname)
        resolved_ip = ascii_hostname
    except ValueError:
        resolved_ip = await _resolve(ascii_hostname)

    # 8a. Cloud metadata IPs — ALWAYS blocked
    if resolved_ip in ALWAYS_BLOCKED_IPS:
        raise ValueError(f"Target resolves to a cloud metadata IP ({resolved_ip}).")

    # 8b. Private ranges — blocked unless allowed
    if not allow_private and is_private_ip(resolved_ip):
        raise ValueError(f"Target resolves to a private/reserved IP ({resolved_ip}).")

    # 9. Reconstruct canonical URL
    path = parsed.path or "/"
    netloc = ascii_hostname
    if ":" in ascii_hostname:  # IPv6
        netloc = f"[{ascii_hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"

    canonical_url = urlunparse((scheme, netloc, path, "", parsed.query, ""))

    try:
        return SanitizedTarget(
            original=target,
            scheme=scheme,
            hostname=ascii_hostname,
            port=port,
            resolved_ip=resolved_ip,
            path=path,
            url=canonical_url,
        )
    except ValidationError as e:
        raise ValueError(f"Internal normalization error: {e}")