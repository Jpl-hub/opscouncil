from __future__ import annotations

import ipaddress


def classify_listener_scope(address: str) -> str:
    host = _listener_host(address)
    if not host:
        return "unknown"
    if host == "*":
        return "wildcard"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    if ip.is_unspecified:
        return "wildcard"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    if ip.is_global:
        return "public"
    return "unknown"


def _listener_host(address: str) -> str:
    value = address.strip()
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        host = value[1 : value.index("]")]
    elif ":" in value:
        host = value.rsplit(":", 1)[0]
    else:
        host = value
    return host.split("%", 1)[0].strip().lower()
