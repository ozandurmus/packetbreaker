import ipaddress
import math
import json
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, model_validator, field_validator


class Point(BaseModel):
    id: str = Field(min_length=1, max_length=80, pattern=r"^[\w-]+$")
    label: str = Field(min_length=1, max_length=100)
    device: str = Field(min_length=1, max_length=100)
    kind: Literal[
        "Client", "Firewall", "IPS", "Router/Switch", "Load Balancer", "Proxy", "WAF", "Server", "Generic"
    ] = "Generic"
    side: Literal["ingress", "egress", "both"] = "both"
    capture_id: str
    clock_domain: str | None = Field(default=None, max_length=100)
    host_capture: bool = False
    stage_capture: bool = False
    interface: int | None = Field(default=None, ge=0)
    vendor: Literal["none", "checkpoint", "f5", "paloalto", "fortinet"] = "none"
    vendor_stage: str | None = None
    vendor_interface: str | None = Field(default=None, max_length=100)
    inspection_complete: bool = False
    matching_layer: Literal["inner", "outer"] | None = None
    source_cidr: str | None = None
    translation: Literal["none", "nat", "full_proxy", "seq_randomization"] = "none"
    payload_transform: Literal["none", "proxy", "alg", "ssl_inspection"] = "none"
    x: float = 0
    y: float = 0

    @model_validator(mode="after")
    def valid(self):
        if self.vendor == "checkpoint" and self.vendor_stage not in (
            "i",
            "I",
            "o",
            "O",
            "e",
            "E",
            "oe",
            "OE",
        ):
            raise ValueError("Choose a Check Point inspection stage")
        if self.vendor == "paloalto" and self.vendor_stage not in ("receive", "firewall", "transmit", "drop"):
            raise ValueError("Choose a Palo Alto capture stage")
        if self.vendor == "paloalto" and self.vendor_stage in ("receive", "transmit"):
            self.side = "ingress" if self.vendor_stage == "receive" else "egress"
        if self.vendor == "f5":
            if self.vendor_stage not in ("client", "server"):
                raise ValueError("Choose the F5 client or server leg")
            self.translation = "full_proxy"
        if self.source_cidr:
            ipaddress.ip_network(self.source_cidr, strict=False)
        if not math.isfinite(self.x) or not math.isfinite(self.y):
            raise ValueError("Coordinates must be finite")
        return self


class NatMapping(BaseModel):
    point_a: str
    point_b: str
    tuple_a: str
    tuple_b: str

    @field_validator("tuple_a", "tuple_b")
    @classmethod
    def valid_tuple(cls, value):
        parts = json.loads(value)
        if not isinstance(parts, list) or len(parts) != 5:
            raise ValueError(
                "NAT tuple must be [protocol, source IP, source port, destination IP, destination port]"
            )
        proto, src, sport, dst, dport = parts
        if proto not in ("TCP", "UDP", "ICMP", "ICMPv6", "GRE"):
            raise ValueError("Unsupported NAT protocol")
        ipaddress.ip_address(src)
        ipaddress.ip_address(dst)
        if any(type(p) is not int or not 0 <= p <= 65535 for p in (sport, dport)):
            raise ValueError("Ports must be integers between 0 and 65535")
        return json.dumps(parts, separators=(",", ":"))


class Override(BaseModel):
    offset_ms: float = Field(allow_inf_nan=False)
    drift_ppm: float = Field(default=0, ge=-5000, le=5000, allow_inf_nan=False)


class Topology(BaseModel):
    cycle_stall_ms: float = Field(default=100, ge=1, le=60000, allow_inf_nan=False)
    cycle_top_n: int = Field(default=20, ge=1, le=100)
    rtp_port_ranges: list[tuple[int, int]] = Field(default_factory=list, max_length=16)
    rtp_clock_rate: int | None = Field(default=None, ge=1000, le=192000)
    rtp_jitter_ms: float = Field(default=2, ge=0.1, le=1000, allow_inf_nan=False)
    udp_timeout_ms: float = Field(default=2000, ge=100, le=60000, allow_inf_nan=False)
    security_half_open_floor: int = Field(default=20, ge=2, le=100000)
    security_scan_window_seconds: float = Field(default=5, ge=1, le=300, allow_inf_nan=False)
    security_scan_targets: int = Field(default=20, ge=2, le=100000)
    security_scan_failed_ratio: float = Field(default=0.8, ge=0.5, le=1, allow_inf_nan=False)
    security_syn_rate: float = Field(default=50, ge=1, le=1000000, allow_inf_nan=False)
    security_completion_ratio: float = Field(default=0.2, ge=0, le=0.5, allow_inf_nan=False)
    security_min_sources: int = Field(default=20, ge=2, le=100000)
    security_sustained_buckets: int = Field(default=3, ge=2, le=1000)
    session_timeout_seconds: float = Field(default=10, ge=1, le=300, allow_inf_nan=False)
    microburst_window_ms: float = Field(default=1, ge=1, le=10, allow_inf_nan=False)
    dns_timeout_ms: float = Field(default=2000, ge=100, le=60000, allow_inf_nan=False)
    bucket_seconds: float = Field(default=1, ge=0.1, le=3600, allow_inf_nan=False)
    report_timezone: str | None = None
    points: list[Point] = Field(default_factory=list, max_length=64)
    forward: list[str] = Field(default_factory=list)
    reverse: list[str] = Field(default_factory=list)
    client_cidrs: list[str] = Field(default_factory=lambda: ["10.0.0.0/8"])
    nat_mappings: list[NatMapping] = Field(default_factory=list, max_length=10000)
    clock_overrides: dict[str, Override] = Field(default_factory=dict)
    min_eligible_ratio: float = Field(default=0.9, ge=0, le=1, allow_inf_nan=False)
    duplicate_us: float = Field(default=20, ge=0, le=100, allow_inf_nan=False)
    stall_ms: float = Field(default=200, ge=1, le=60000)
    match_window_ms: float = Field(default=2000, ge=1, le=60000)
    start: float | None = Field(default=None, allow_inf_nan=False)
    end: float | None = Field(default=None, allow_inf_nan=False)

    def path(self, direction):
        return self.forward if direction == "forward" else self.reverse or self.forward[::-1]

    def precedes(self, a, b, direction):
        path = self.path(direction)
        return a in path and b in path and path.index(a) < path.index(b)

    @model_validator(mode="after")
    def valid(self):
        domains = {}
        for p in self.points:
            if p.clock_domain:
                if p.capture_id in domains and domains[p.capture_id] != p.clock_domain:
                    raise ValueError("One capture file cannot belong to conflicting clock domains")
                domains[p.capture_id] = p.clock_domain
        for domain in set(domains.values()):
            corrections = {
                (self.clock_overrides[cid].offset_ms, self.clock_overrides[cid].drift_ppm)
                for cid, name in domains.items()
                if name == domain and cid in self.clock_overrides
            }
            if len(corrections) > 1:
                raise ValueError("Shared clock domain has conflicting clock corrections")
        stage_devices = {p.device for p in self.points if p.stage_capture}
        if stage_devices:
            from itertools import groupby

            points = {p.id: p for p in self.points}
            if any(p not in points for p in self.forward + self.reverse):
                raise ValueError("Paths must contain existing capture points")
            for p in self.points:
                if p.device in stage_devices:
                    p.stage_capture = True
                    if p.side not in ("ingress", "egress"):
                        raise ValueError("Stage captures require rx/ingress or tx/egress side")

            def stage_order(path):
                result = []
                for device, block in groupby(path, key=lambda p: points[p].device):
                    block = list(block)
                    if device in stage_devices:
                        block.sort(key=lambda p: points[p].side != "ingress")
                    result.extend(block)
                return result

            self.forward = stage_order(self.forward)
            self.reverse = stage_order(self.reverse or self.forward[::-1])
        if any(not 1 <= a <= b <= 65535 for a, b in self.rtp_port_ranges):
            raise ValueError("RTP port ranges must be ordered UDP ports 1..65535")
        if self.report_timezone:
            try:
                ZoneInfo(self.report_timezone)
            except ZoneInfoNotFoundError as exc:
                raise ValueError("Unknown IANA time zone") from exc
        ids = [p.id for p in self.points]
        if len(ids) != len(set(ids)):
            raise ValueError("Capture point IDs must be unique")
        for path in (self.forward, self.reverse):
            if len(path) != len(set(path)) or any(p not in ids for p in path):
                raise ValueError("Paths must contain existing capture points once; cycles are unsupported")
        paloalto_files = {}
        for p in self.points:
            if p.vendor == "paloalto":
                paloalto_files.setdefault(p.capture_id, set()).add((p.device, p.vendor_stage))
        if any(len(tags) > 1 for tags in paloalto_files.values()):
            raise ValueError("Each Palo Alto stage file must have one node/stage tag")
        checkpoint_nodes = {}
        for p in self.points:
            if p.vendor == "checkpoint":
                checkpoint_nodes.setdefault(p.capture_id, set()).add(p.device)
        if any(len(devices) > 1 for devices in checkpoint_nodes.values()):
            raise ValueError("A fw monitor file must map to inspection points of one node")
        for cidr in self.client_cidrs:
            ipaddress.ip_network(cidr, strict=False)
        if not self.client_cidrs:
            raise ValueError("At least one client CIDR is required to define direction")
        if self.start is not None and self.end is not None and self.start >= self.end:
            raise ValueError("Time window start must precede end")
        return self
