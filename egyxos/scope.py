"""Target and scope validation. Validation is deliberately conservative."""

import ipaddress
import re
from urllib.parse import urlparse

from .errors import ScopeError

_HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def normalize_target(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ScopeError("A target is required.")
    candidate = value
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ScopeError("Only http(s) URLs are accepted as targets.", details={"target": value})
        candidate = parsed.hostname
    candidate = candidate.rstrip(".").lower()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    try:
        network = ipaddress.ip_network(candidate, strict=False)
        return str(network)
    except ValueError:
        pass
    if not _HOST.match(candidate) or "." not in candidate:
        raise ScopeError("Target must be a hostname, IP address, CIDR, or http(s) URL.", details={"target": value})
    return candidate


def validate_scope(target: str, *, allow_private: bool = False) -> str:
    normalized = normalize_target(target)
    try:
        address = ipaddress.ip_address(normalized)
        if (address.is_private or address.is_loopback or address.is_link_local) and not allow_private:
            raise ScopeError("Private or loopback targets require --allow-private.")
    except ValueError:
        try:
            network = ipaddress.ip_network(normalized, strict=False)
            if (network.is_private or network.is_loopback or network.is_link_local) and not allow_private:
                raise ScopeError("Private network targets require --allow-private.")
        except ValueError:
            pass
    return normalized


def in_scope(value: str, target: str) -> bool:
    """Return whether a discovered host is within the requested host/network."""
    try:
        address = ipaddress.ip_address(value)
        network = ipaddress.ip_network(target, strict=False)
        return address in network
    except ValueError:
        host = value.lower().rstrip(".")
        root = target.lower().rstrip(".")
        return host == root or host.endswith("." + root)
