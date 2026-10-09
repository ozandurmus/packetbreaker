"""On-demand, frame-backed handshake and bounded cleartext HTTP/1.x timelines."""

import re

from .evidence import evidence
from .store import rows

MOD = 2**32
LIMIT = 20000
REQUEST = re.compile(rb"[A-Z]+ [^\r\n]+ HTTP/1\.[01]\r\n")
RESPONSE = re.compile(rb"HTTP/1\.[01] ([2-5][0-9]{2})[ \r]")


def request_size(packet, packets):
    """Read only contiguous captured header bytes; never fill prefix gaps."""
    data = bytearray()
    for p in sorted(packets, key=lambda p: (p["seq"] - packet["seq"]) % MOD):
        offset = (p["seq"] - packet["seq"]) % MOD
        if offset > len(data) or offset >= 8192:
            break
        payload = bytes.fromhex(p["prefix"] or "")
        overlap = min(len(payload), len(data) - offset)
        if data[offset : offset + overlap] != payload[:overlap]:
            return None, "Conflicting captured HTTP header bytes"
        data.extend(payload[overlap : 8192 - len(data) + overlap])
        if b"\r\n\r\n" in data:
            break
    header, sep, _ = bytes(data).partition(b"\r\n\r\n")
    if not sep:
        return None, "HTTP headers incomplete in captured prefixes (8 KiB header limit)"
    fields = [line.split(b":", 1) for line in header.split(b"\r\n")[1:]]
    if any(len(f) != 2 for f in fields):
        return None, "Malformed HTTP request headers"
    headers = [(k.strip().lower(), v.strip()) for k, v in fields]
    if any(k == b"transfer-encoding" for k, _ in headers):
        return None, "HTTP transfer-encoding request boundary is unknown; chunk decoding is not supported"
    lengths = [v for k, v in headers if k == b"content-length"]
    if lengths and (len(set(lengths)) != 1 or not lengths[0].isdigit()):
        return None, "Ambiguous HTTP Content-Length"
    body = int(lengths[0]) if lengths else 0
    if body > 8 * 1024 * 1024:
        return None, "HTTP request exceeds the 8 MiB request tracking limit"
    return len(header) + 4 + body, None


def completion(packets, seed, size, before):
    covered = []
    for p in sorted(packets, key=lambda x: (x["ts"], x["frame"])):
        if p["ts"] < seed["ts"] or p["ts"] > before or not p["eligible"]:
            continue
        lo = (p["seq"] - seed["seq"]) % MOD
        hi = min(size, lo + p["length"])
        if lo >= size or hi <= lo:
            continue
        covered.append((lo, hi))
        end = 0
        for a, b in sorted(covered):
            if a > end:
                break
            end = max(end, b)
        if end >= size:
            return p
    return None


def waterfall(project, flow, start=None, end=None, request_index=0):
    with project.connect() as db:
        report = project.get(db, "report")
        topology = project.get(db, "topology")
        if not report or not topology:
            return dict(items=[], requests=[], reason="Run analysis first")
        packets = rows(
            db,
            """SELECT * FROM obs WHERE flow=? AND proto='TCP'
            ORDER BY ts,point,frame LIMIT ?""",
            [flow, LIMIT + 1],
        )
        if len(packets) > LIMIT:
            return dict(items=[], requests=[], reason="Flow exceeds the 20,000-observation waterfall budget")
        points = {p["id"]: p for p in topology["points"]}
        forward = topology["forward"]
        reverse = topology["reverse"] or list(reversed(forward))
        if len(forward) < 2:
            return dict(items=[], requests=[], reason="An ordered path with at least two points is required")
        client, server = forward[0], forward[-1]
        by_point = {p: [x for x in packets if x["point"] == p] for p in points}
        full_proxy = any(p["translation"] == "full_proxy" for p in points.values())
        fallback = "unknown (full proxy, Phase 3)" if full_proxy else "Missing or unmatchable endpoint frame"
        refs = {}

        def frame_refs(*frames):
            result = []
            for p in frames:
                if not p:
                    continue
                key = (p["point"], p["frame"])
                if key not in refs:
                    refs[key] = evidence(db, "o.point=? AND o.frame=?", list(key), 1, _expand_ranges=False)
                if refs[key] and refs[key][0] not in result:
                    result.extend(refs[key])
            return result

        def trace(seed, first=False):
            if not seed:
                return {}
            found = {
                p["point"]: p for p in packets if p["packet_key"] == seed["packet_key"] and p["eligible"]
            }
            # A segmentation boundary can identify a physical parent through shared byte occurrences.
            if db.execute("SELECT count(*) FROM byte_flows WHERE flow=?", [flow]).fetchone()[0]:
                peers = db.execute(
                    """SELECT DISTINCT b.point,b.source_frame FROM byte_obs a JOIN byte_obs b
                    USING(packet_key) WHERE a.point=? AND a.source_frame=? AND a.is_atom AND b.is_atom
                    AND a.eligible AND b.eligible AND (NOT ? OR (a.lo<=? AND a.hi>?))""",
                    [seed["point"], seed["frame"], first, seed["seq"], seed["seq"]],
                ).fetchall()
                candidates = [p for p in packets if (p["point"], p["frame"]) in peers and p["eligible"]]
                for p in candidates:
                    # Completion uses the last delivered component of a coalesced captured unit.
                    if p["point"] not in found or (
                        p["ts"] < found[p["point"]]["ts"] if first else p["ts"] > found[p["point"]]["ts"]
                    ):
                        found[p["point"]] = p
            return found

        def bar(a, b, label, kind, direction, pa, pb, origin, reason=None):
            ma = report["clocks"].get(points[pa]["capture_id"], {})
            mb = report["clocks"].get(points[pb]["capture_id"], {})
            uncertainty = None
            if any(points[p]["translation"] == "full_proxy" for p in (pa, pb)) and pa != pb:
                reason = "unknown (full proxy, Phase 3)"
            if not a or not b or not a["eligible"] or not b["eligible"]:
                reason = reason or fallback
            if a and b and a["corrected"] is not None and b["corrected"] is not None:
                if ma.get("uncertainty") is not None and mb.get("uncertainty") is not None:
                    uncertainty = (
                        0
                        if a["capture_id"] == b["capture_id"]
                        else 1000 * (ma["uncertainty"] + mb["uncertainty"])
                    )
                if (
                    uncertainty is None
                    or ma.get("confidence") == "unknown"
                    or mb.get("confidence") == "unknown"
                ):
                    reason = reason or "Clock alignment unreliable or uncertainty unverified"
                duration = (b["corrected"] - a["corrected"]) * 1000
                if duration < 0:
                    reason = reason or "Clock/order inconsistency: negative elapsed time"
            else:
                duration = None
                reason = reason or "Clock alignment unreliable"
            segment = next(
                (
                    s
                    for s in report["segments"]
                    if s["point_a"] == pa and s["point_b"] == pb and s["direction"] == direction
                ),
                None,
            )
            if segment and segment.get("reason"):
                reason = reason or segment["reason"]
            return dict(
                label=label,
                kind=kind,
                direction=direction,
                point_a=pa,
                point_b=pb,
                duration_ms=None if reason else duration,
                uncertainty_ms=uncertainty,
                start_ms=(a["corrected"] - origin) * 1000
                if a and a["corrected"] is not None and origin is not None and not reason
                else None,
                reason=reason,
                evidence=frame_refs(a, b),
                note="Same-capture offset cancels; timestamp precision and residual drift remain approximate"
                if pa == pb
                else "Clock-corrected estimate; coalesced-frame timestamps are not individual wire timestamps",
            )

        def legs(seed, path, label, direction, origin, first=False):
            matched = trace(seed, first)
            return [
                bar(
                    matched.get(a),
                    matched.get(b),
                    f"{label}: {points[a]['label']} → {points[b]['label']}",
                    "device_dwell" if points[a]["device"] == points[b]["device"] else "link",
                    direction,
                    a,
                    b,
                    origin,
                )
                for a, b in zip(path, path[1:])
            ]

        def in_window(p):
            return (start is None or (p["corrected"] is not None and p["corrected"] >= start)) and (
                end is None or (p["corrected"] is not None and p["corrected"] < end)
            )

        items = []
        syn = next((p for p in by_point[client] if p["flags"] & 18 == 2 and in_window(p)), None)
        syns = trace(syn)
        sa = next(
            (
                p
                for p in by_point[server]
                if syn
                and p["flags"] & 18 == 18
                and p["ack"] == (syn["seq"] + 1) % MOD
                and p["ts"] >= syns.get(server, syn)["ts"]
            ),
            None,
        )
        sas = trace(sa)
        ack = next(
            (
                p
                for p in by_point[client]
                if sa
                and p["flags"] & 18 == 16
                and p["ack"] == (sa["seq"] + 1) % MOD
                and p["seq"] == (syn["seq"] + 1) % MOD
                and p["ts"] >= sas.get(client, sa)["ts"]
            ),
            None,
        )
        origin = syn["corrected"] if syn else None
        bars = legs(syn, forward, "SYN", "forward", origin)
        bars += [
            bar(
                syns.get(server),
                sa,
                "Server SYN → SYN/ACK turnaround",
                "server_turnaround",
                "reverse",
                server,
                server,
                origin,
            )
        ]
        bars += legs(sa, reverse, "SYN/ACK", "reverse", origin)
        bars += [
            bar(
                sas.get(client),
                ack,
                "Client SYN/ACK → ACK turnaround",
                "client_turnaround",
                "forward",
                client,
                client,
                origin,
            )
        ]
        bars += legs(ack, forward, "ACK", "forward", origin)
        items.append(dict(kind="handshake", title="TCP three-way handshake", bars=bars, origin=origin))

        candidates = [
            p
            for p in (by_point[server] or by_point[client])
            if p["direction"] == "forward"
            and p["length"] > 0
            and REQUEST.match(bytes.fromhex(p["prefix"] or ""))
            and in_window(p)
        ]
        candidates = list({p["seq"]: p for p in reversed(candidates)}.values())
        candidates.sort(key=lambda p: p["ts"])
        choices = [
            dict(
                index=i,
                label=bytes.fromhex(p["prefix"]).split(b"\r\n")[0].decode("ascii", "replace"),
                time=p["corrected"],
            )
            for i, p in enumerate(candidates[:100])
        ]
        if candidates and request_index < min(len(candidates), 100):
            req = candidates[request_index]
            local = [
                p
                for p in by_point[req["point"]]
                if p["direction"] == "forward" and p["length"] > 0 and p["ts"] >= req["ts"]
            ]
            size, reason = request_size(req, local)
            response = next(
                (
                    p
                    for p in by_point[server]
                    if p["direction"] == "reverse"
                    and p["ts"] > req["ts"]
                    and RESPONSE.match(bytes.fromhex(p["prefix"] or ""))
                    and size is not None
                    and (p["ack"] - req["seq"]) % MOD >= size
                    and (p["ack"] - req["seq"]) % MOD < MOD // 2
                ),
                None,
            )
            if (
                response
                and request_index + 1 < len(candidates)
                and candidates[request_index + 1]["ts"] < response["ts"]
            ):
                reason = "HTTP pipelining/overlap: response association unknown"
            last = completion(local, req, size, response["ts"]) if size is not None and response else None
            first_request = next(
                (
                    p
                    for p in by_point[client]
                    if p["direction"] == "forward" and p["seq"] == req["seq"] and p["length"] > 0
                ),
                None,
            )
            origin = (first_request or req)["corrected"]
            bars = [
                bar(
                    first_request,
                    trace(last).get(client),
                    "Client request transmission / retry span",
                    "request_transmission",
                    "forward",
                    client,
                    client,
                    origin,
                )
            ]
            bars += legs(last, forward, "Request completion", "forward", origin)
            bars += [
                bar(
                    last if req["point"] == server else None,
                    response,
                    "Server processing: last request byte → first response byte",
                    "server_processing",
                    "reverse",
                    server,
                    server,
                    origin,
                    reason,
                )
            ]
            bars += legs(response, reverse, "First response byte", "reverse", origin, first=True)
            items.append(
                dict(
                    kind="http",
                    title=choices[request_index]["label"],
                    bars=bars,
                    origin=origin,
                    note="Request completion and time to first response byte; not response-body download time. Up to 100 requests selectable. Chunked requests and pipelining stay unknown.",
                )
            )
        return dict(
            items=items,
            requests=choices,
            reason=None
            if candidates
            else "No captured cleartext HTTP/1.x request line in this window; TLS is not decoded",
        )
