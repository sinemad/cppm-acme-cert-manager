"""DNS helpers for split-horizon handling of ACME DNS-01 challenges.

Lego uses resolvers for two things during DNS-01: finding the zone that owns
the challenge name (SOA lookups walking up the labels) and finding the
authoritative nameservers to confirm the TXT record has propagated. By default
it uses the container's resolvers (Docker ``dns:``). In a split-horizon setup
those resolvers serve an *internal* copy of the zone, so Lego looks at the
wrong zone. Pointing Lego at public resolvers (``--dns.resolvers``) fixes that
without changing how the rest of the container resolves names.

All lookups here are read-only and use ``dig`` (bind-tools in the image).
"""
from __future__ import annotations

import ipaddress
import re
import subprocess

# Used when split-horizon is enabled and no custom resolvers are configured.
DEFAULT_PUBLIC_RESOLVERS: tuple[str, ...] = ("1.1.1.1:53", "8.8.8.8:53")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)


def normalize_resolver(value: str) -> str:
    """Return ``value`` as ``host:port`` (default port 53), as Lego expects.

    Accepts IPv4, IPv6 (bare or ``[addr]`` / ``[addr]:port``) and hostnames,
    each with an optional port. Raises ValueError on anything else.
    """
    v = value.strip()
    if not v:
        raise ValueError("empty resolver")

    host, port = v, "53"
    if v.startswith("["):
        m = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", v)
        if not m:
            raise ValueError(f"invalid resolver '{value}'")
        host, port = m.group(1), m.group(2) or "53"
        ipaddress.IPv6Address(host)  # raises ValueError
        return f"[{host}]:{_check_port(port, value)}"
    if v.count(":") > 1:
        # Bare IPv6 address (no brackets, so no port).
        ipaddress.IPv6Address(v)
        return f"[{v}]:53"
    if ":" in v:
        host, port = v.rsplit(":", 1)
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host) or host.replace(".", "").isdigit():
            raise ValueError(f"invalid resolver '{value}'") from None
    return f"{host}:{_check_port(port, value)}"


def _check_port(port: str, original: str) -> str:
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"invalid port in resolver '{original}'")
    return port


def parse_resolvers(values) -> list[str]:
    """Normalize a list (or comma/space/newline separated string) of resolvers.

    Raises ValueError naming the first invalid entry.
    """
    if isinstance(values, str):
        values = re.split(r"[,\s]+", values)
    result: list[str] = []
    for item in values or []:
        if str(item).strip():
            r = normalize_resolver(str(item))
            if r not in result:
                result.append(r)
    return result


def _dig_server_arg(resolver: str) -> list[str]:
    """Split a normalized ``host:port`` into dig's ``@host -p port`` args."""
    if resolver.startswith("["):
        host, port = resolver[1:].split("]:", 1)
    else:
        host, port = resolver.rsplit(":", 1)
    return [f"@{host}", "-p", port]


def find_zone(name: str, resolver: str | None = None, timeout: int = 2) -> tuple[str, str] | None:
    """Return ``(zone, primary_ns)`` for the zone that owns ``name``.

    Walks up the labels asking for SOA records, the same way Lego finds the
    zone. ``resolver`` is a normalized ``host:port``; None uses the container's
    own resolvers. Returns None if no SOA is found or dig is unavailable /
    the resolver can't be reached.
    """
    labels = name.strip().rstrip(".").lstrip("*.").split(".")
    server_args = _dig_server_arg(resolver) if resolver else []
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        try:
            proc = subprocess.run(
                ["dig", *server_args, "+short", f"+time={timeout}", "+tries=1",
                 "SOA", candidate],
                capture_output=True, text=True, timeout=timeout * 2 + 2,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            # 9 = no reply from server; anything else is also not an answer.
            return None
        for line in proc.stdout.splitlines():
            parts = line.split()
            # A +short SOA answer is: mname rname serial refresh retry expire minimum.
            # A CNAME answer is a single name; skip it and keep walking.
            if len(parts) == 7:
                return candidate.lower(), parts[0].rstrip(".").lower()
    return None


def split_horizon_check(domain: str, enabled: bool, resolvers: list[str]) -> dict | None:
    """Compare the zone seen by the container's DNS with the one seen publicly.

    Returns None when everything looks right (or can't be determined), else a
    dict ``{"status": "warn", "message": ...}`` for the health check / logs.

    - Not enabled: warn if the container sees a different zone (or a different
      primary nameserver) than public DNS — that's a split-horizon setup.
    - Enabled: warn if none of the configured resolvers answer, since Lego
      would then fail to find the zone at all.
    """
    if not domain:
        return None
    if enabled:
        for r in resolvers or DEFAULT_PUBLIC_RESOLVERS:
            if find_zone(domain, r):
                return None
        return {
            "status": "warn",
            "message": ("Split-horizon DNS is enabled, but the challenge resolvers ("
                        + ", ".join(resolvers or DEFAULT_PUBLIC_RESOLVERS)
                        + ") did not answer. Certificate validation will fail if they "
                          "are blocked on this network."),
        }

    public = None
    for r in DEFAULT_PUBLIC_RESOLVERS:
        public = find_zone(domain, r)
        if public:
            break
    local = find_zone(domain)
    if not public or not local:
        return None  # can't tell (public DNS blocked, or no answer locally)
    if public == local:
        return None
    return {
        "status": "warn",
        "message": (f"Container DNS returns an internal version of {local[0]} "
                    f"(primary NS {local[1]}) but public DNS shows {public[0]} "
                    f"(primary NS {public[1]}). Certificate validation will likely time "
                    "out. Enable \"split-horizon DNS\" under Advanced in this "
                    "server's settings."),
    }
