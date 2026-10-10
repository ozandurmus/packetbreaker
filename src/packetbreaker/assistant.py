"""Local findings redaction preview. No provider, credentials or network client."""

from ipaddress import ip_address
import re
from urllib.parse import urlsplit

from .export import export_data


IP = re.compile(
    r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?:%[\w-]+)?"
    r"|(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)"
)
HOST = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w-]|\.[a-zA-Z0-9-])"
)
CN = re.compile(r"\bCN\s*=\s*([^,;/\s]+)", re.IGNORECASE)
HOST_KEYS = {"host", "hostname", "sni", "server_name", "http.host", "tls.handshake.extensions_server_name"}
# These are filter/schema identifiers, not hostnames. Raw evidence filters retain their grammar.
IDENTIFIERS = {
    "packetbreaker.findings",
    "frame.number",
    "ip.src",
    "ip.dst",
    "ip.addr",
    "ip.id",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.addr",
    "tcp.len",
    "tcp.flags",
    "tcp.port",
    "tcp.srcport",
    "tcp.dstport",
    "udp.port",
    "udp.srcport",
    "udp.dstport",
    "icmp.ident",
    "icmp.seq",
    "icmpv6.echo.identifier",
    "icmpv6.echo.sequence_number",
    "dns.id",
    "dns.flags.response",
    "ipv6.flow",
    "udp.length",
    "icmp.type",
    "icmpv6.type",
    "fw1.direction",
    "fw1.chain",
    "http.host",
    "frame.time_epoch",
}


def redact_findings(value):
    """Fresh deterministic tokens per preview; never return the raw token dictionary."""
    tokens = {}
    counts = {"IP": 0, "HOST": 0}
    known_hosts = set()

    def collect(item, key=""):
        if isinstance(item, dict):
            for k, v in item.items():
                collect(v, k.lower())
        elif isinstance(item, list):
            for v in item:
                collect(v, key)
        elif isinstance(item, str):
            known_hosts.update(m.group(1).casefold().rstrip(".") for m in CN.finditer(item))
            if key in HOST_KEYS and item:
                known_hosts.add((urlsplit("//" + item).hostname or item).casefold().rstrip("."))

    collect(value)

    def token(kind, raw):
        identity = (kind, raw)
        if identity not in tokens:
            counts[kind] += 1
            tokens[identity] = f"{kind}_{counts[kind]:03d}"
        return tokens[identity]

    def address(match):
        raw = match.group()
        # A sentence-ending dot is punctuation, not part of the IPv6 address.
        clean = raw.rstrip(".")
        try:
            return token("IP", str(ip_address(clean))) + raw[len(clean) :]
        except ValueError:
            return raw

    def hostname(match):
        raw = match.group()
        return raw if raw.casefold() in IDENTIFIERS else token("HOST", raw.casefold())

    def text(raw):
        result = IP.sub(address, raw)
        result = HOST.sub(hostname, result)
        for host in sorted(known_hosts, key=lambda h: (-len(h), h)):
            # FQDNs and addresses were handled above; this also covers single-label names.
            result = re.sub(
                r"(?<![\w.-])" + re.escape(host) + r"(?![\w.-])",
                lambda m: token("HOST", host),
                result,
                flags=re.IGNORECASE,
            )
        return result

    def visit(item):
        if isinstance(item, dict):
            return {text(k): visit(v) for k, v in item.items()}
        if isinstance(item, list):
            return [visit(v) for v in item]
        return text(item) if isinstance(item, str) else item

    return visit(value)


def preview(project):
    return redact_findings(export_data(project, findings_only=True))
