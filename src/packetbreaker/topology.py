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
    interface: int | None = Field(default=None, ge=0)
    vendor: Literal["none", "checkpoint", "f5", "paloalto", "fortinet"] = "none"
    vendor_stage: str | None = None
    inspection_complete: bool = False
    source_cidr: str | None = None
    translation: Literal["none", "nat", "full_proxy", "seq_randomization"] = "none"
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
        if proto not in ("TCP", "UDP", "ICMP"):
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

    @model_validator(mode="after")
    def valid(self):
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
