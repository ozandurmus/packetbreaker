"""Request-level waterfall across distinct proxy legs; never matches their packets."""

import json
from .store import rows
from .proxy_analysis import refs, uncertainty
from .clock import ClockModel
from .topology import Topology


def interval(a, b, uncertainty_s):
    reason = None
    if a is None or b is None:
        reason = "Application byte boundary unavailable"
    elif uncertainty_s is None:
        reason = "Clock alignment unreliable or uncertainty unverified"
    elif b < a:
        reason = "Streaming/order or clock inconsistency: request forwarded before ingress completion"
    return dict(
        duration_ms=None if reason else (b - a) * 1000,
        uncertainty_ms=None if uncertainty_s is None else uncertainty_s * 1000,
        reason=reason,
    )


def add_dwell(db, topology, models, proxies):
    points = {p.id: p for p in topology.points}
    lookup = {r["id"]: r for r in rows(db, "SELECT * FROM proxy_requests")}
    # Persist every pairing, even when the interactive overview is capped.
    pairs = [json.loads(r[0]) for r in db.execute("SELECT metadata FROM proxy_pairs").fetchall()]
    for p in pairs:
        c, s = lookup.get(p["client_id"]), lookup.get(p["server_id"])
        u = uncertainty(models, points[p["point_a"]], points[p["point_b"]])
        p["request_dwell"] = interval(c["complete"] if c else None, s["start"] if s else None, u)
        p["response_dwell"] = interval(s["response"] if s else None, c["response"] if c else None, u)
        if p["status"] != "matched":
            for key in ("request_dwell", "response_dwell"):
                p[key].update(duration_ms=None, reason=p["reason"])
        if p["kind"] == "tls_setup":
            for key in ("request_dwell", "response_dwell"):
                p[key].update(
                    duration_ms=None,
                    reason="TLS setup pairing; encrypted application request boundaries unknown",
                )
        db.execute(
            "UPDATE proxy_pairs SET metadata=? WHERE device=? AND client_id IS NOT DISTINCT FROM ? AND server_id IS NOT DISTINCT FROM ?",
            [json.dumps(p), p["device"], p["client_id"], p["server_id"]],
        )
    proxies["transactions"] = pairs[:200]


def waterfall(db, report, topology, flow, start, end, request_index):
    topology = Topology.model_validate(topology)
    requests = rows(
        db, "SELECT * FROM proxy_requests WHERE kind='http' ORDER BY start,point,last_frame LIMIT 20001"
    )
    if len(requests) > 20000:
        return dict(
            items=[],
            requests=[],
            reason="Proxy waterfall exceeds 20,000 request observations; narrow capture",
        )
    byid = {r["id"]: r for r in requests}

    def alias(a, b):
        return (
            a["flow"] == b["flow"]
            and a["start_seq"] == b["start_seq"]
            and a["line"] == b["line"]
            and a["host"] == b["host"]
        )

    pairs = [
        json.loads(r[0])
        for r in db.execute("SELECT metadata FROM proxy_pairs WHERE status='matched'").fetchall()
    ]

    def root(r):
        seen = set()
        while r["id"] not in seen:
            seen.add(r["id"])
            candidates = [
                byid[p["client_id"]]
                for p in pairs
                if p["client_id"] in byid and p["server_id"] in byid and alias(r, byid[p["server_id"]])
            ]
            if len(candidates) != 1:
                break
            r = candidates[0]
        return r

    seeds = {
        root(r)["id"]: root(r)
        for r in requests
        if r["flow"] == flow
        and (start is None or r["start"] is not None and r["start"] >= start)
        and (end is None or r["start"] is not None and r["start"] < end)
    }
    seeds = sorted(seeds.values(), key=lambda r: r["start"] or 0)[:100]
    choices = [dict(index=i, label=r["line"], time=r["start"]) for i, r in enumerate(seeds)]
    if request_index >= len(seeds):
        return dict(
            items=[],
            requests=choices,
            reason="No uniquely correlated cleartext HTTP/1.x request for this leg/window",
        )
    seed = seeds[request_index]
    points = {p.id: p for p in topology.points}
    stage = {r["point"]: r for r in requests if alias(seed, r)}
    for _ in range(len(topology.points)):
        changed = False
        for p in pairs:
            c, s = byid.get(p["client_id"]), byid.get(p["server_id"])
            if (
                c
                and s
                and c["point"] in stage
                and stage[c["point"]]["id"] == c["id"]
                and s["point"] not in stage
            ):
                stage.update({r["point"]: r for r in requests if alias(s, r)})
                changed = True
        if not changed:
            break
    models = {
        cid: ClockModel(**{k: v for k, v in m.items() if k != "drift_ppm"})
        for cid, m in report["clocks"].items()
    }
    bars = []
    origin = seed["start"]

    def bar(a, b, label, kind, direction, ta, tb, ra, rb, reason=None):
        value = interval(ta, tb, uncertainty(models, points[a], points[b]))
        if reason:
            value.update(duration_ms=None, reason=reason)
        return dict(
            label=label,
            kind=kind,
            direction=direction,
            point_a=a,
            point_b=b,
            **value,
            start_ms=(ta - origin) * 1000
            if ta is not None and origin is not None and not value["reason"]
            else None,
            evidence=refs(db, ra, rb),
            note="Request-level correlation; clocks carry uncertainty. These are separate TCP connections.",
        )

    for direction, path in [
        ("forward", topology.forward),
        ("reverse", topology.reverse or topology.forward[::-1]),
    ]:
        for a, b in zip(path, path[1:]):
            ra, rb = stage.get(a), stage.get(b)
            device = points[a].device == points[b].device
            proxy = device and "full_proxy" in (points[a].translation, points[b].translation)
            ta = (
                (
                    ra.get("complete")
                    if proxy and direction == "forward"
                    else ra.get("start")
                    if direction == "forward"
                    else ra.get("response")
                )
                if ra
                else None
            )
            tb = (rb.get("start") if direction == "forward" else rb.get("response")) if rb else None
            reason = (
                None
                if ra and rb and ra["ready"] and rb["ready"]
                else "Request correlation or captured byte boundary unknown"
            )
            if ra and rb and not proxy and not alias(ra, rb):
                reason = "No shared request evidence on this link"
            if ra and rb and proxy:
                c, s = (ra, rb) if direction == "forward" else (rb, ra)
                if not any(p["client_id"] == c["id"] and p["server_id"] == s["id"] for p in pairs):
                    reason = "No unique full-proxy request pair"
            bars.append(
                bar(
                    a,
                    b,
                    f"{points[a].label} → {points[b].label}",
                    "proxy_dwell" if proxy else "device_dwell" if device else "link",
                    direction,
                    ta,
                    tb,
                    ra,
                    rb,
                    reason,
                )
            )
        if direction == "forward":
            last = path[-1]
            r = stage.get(last)
            bars.append(
                bar(
                    last,
                    last,
                    "Server processing",
                    "server_processing",
                    "reverse",
                    r["complete"] if r else None,
                    r["response"] if r else None,
                    r,
                    r,
                )
            )
    return dict(
        items=handshakes(db, topology, models, stage)
        + [
            dict(
                kind="http",
                title=seed["line"],
                bars=bars,
                note="HTTP request graph crosses proxy connections; TCP handshake remains local to each leg.",
            )
        ],
        requests=choices,
        reason=None,
    )


def handshakes(db, topology, models, stage):
    from .evidence import evidence

    result = []
    points = {p.id: p for p in topology.points}
    for flow in sorted({r["flow"] for r in stage.values()}):
        packets = rows(
            db,
            "SELECT * FROM obs WHERE flow=? AND ((flags&2)=2 OR (flags=16 AND length=0)) ORDER BY corrected,frame LIMIT 501",
            [flow],
        )
        route = [p for p in topology.forward if any(o["point"] == p for o in packets)]
        if len(route) < 2:
            continue
        first, last = route[0], route[-1]
        syn = next((p for p in packets if p["point"] == first and p["flags"] & 18 == 2), None)
        sa = next(
            (
                p
                for p in packets
                if p["point"] == last
                and p["flags"] & 18 == 18
                and syn
                and p["ack"] == (syn["seq"] + 1) % 4294967296
            ),
            None,
        )
        ack = next(
            (
                p
                for p in packets
                if p["point"] == first
                and p["flags"] == 16
                and sa
                and p["ack"] == (sa["seq"] + 1) % 4294967296
                and p["corrected"] >= sa["corrected"]
            ),
            None,
        )
        bars = []
        for seed, path, label in [(syn, route, "SYN"), (sa, route[::-1], "SYN/ACK"), (ack, route, "ACK")]:
            matched = {p["point"]: p for p in packets if seed and p["packet_key"] == seed["packet_key"]}
            for a, b in zip(path, path[1:]):
                x, y = matched.get(a), matched.get(b)
                value = interval(
                    x["corrected"] if x else None,
                    y["corrected"] if y else None,
                    uncertainty(models, points[a], points[b]),
                )
                keys = [(p["point"], p["frame"]) for p in (x, y) if p]
                bars.append(
                    dict(
                        label=f"{label}: {points[a].label} → {points[b].label}",
                        kind="link",
                        direction="forward" if label != "SYN/ACK" else "reverse",
                        point_a=a,
                        point_b=b,
                        **value,
                        start_ms=(x["corrected"] - syn["corrected"]) * 1000
                        if x and syn and not value["reason"]
                        else None,
                        evidence=evidence(
                            db,
                            " OR ".join("(o.point=? AND o.frame=?)" for _ in keys),
                            [v for k in keys for v in k],
                            _expand_ranges=False,
                        )
                        if keys
                        else [],
                        note="Handshake belongs to this TCP leg only; no cross-proxy packet identity.",
                    )
                )
        result.append(
            dict(
                kind=f"handshake:{flow}",
                title=f"TCP leg handshake: {points[first].label} → {points[last].label}",
                bars=bars,
            )
        )
    return result
