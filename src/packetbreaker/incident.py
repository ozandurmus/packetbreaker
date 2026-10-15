"""Presentation projections of the existing engine tables, not a second analysis engine."""

from .store import rows
from .evidence import evidence


def attach(db, records):
    bundles = [r.pop("_keys", []) for r in records]
    keys = sorted({(p, f) for bundle in bundles for p, f in bundle if p and f})
    refs = (
        evidence(
            db,
            "(o.point,o.frame) IN (SELECT unnest(?::VARCHAR[]),unnest(?::BIGINT[]))",
            [[p for p, f in keys], [f for p, f in keys]],
            len(keys),
            _expand_ranges=False,
        )
        if keys
        else []
    )
    lookup = {(r["point"], r["frame"]): r for r in refs}
    for r, bundle in zip(records, bundles):
        r["evidence"] = [lookup[k] for k in bundle if k in lookup]
    return records


def build_incident(db, topology, host, cycles, delivery, findings):
    hosts = [p.id for p in topology.points if p.host_capture]
    timeline = (
        rows(
            db,
            """WITH times AS(SELECT DISTINCT start FROM host_path_series UNION SELECT DISTINCT start FROM delivery_series),
        delays AS(SELECT start,max(max_ms) FILTER(WHERE direction='rx') AS rx_max_ms,
         max(max_ms) FILTER(WHERE direction='tx') AS tx_max_ms FROM host_path_series WHERE reason IS NULL GROUP BY start),
        drops AS(SELECT start,sum(dropped) AS tx_dropped,sum(delayed) AS tx_delayed FROM delivery_series
         WHERE point_a IN(SELECT unnest(?::VARCHAR[])) AND direction='reverse' GROUP BY start),
        retrans AS(SELECT floor(coalesce(corrected,ts)) AS start,count(*) AS retransmissions,arg_min(frame,coalesce(corrected,ts)) AS frame,min(point) AS point
         FROM obs WHERE retrans AND point IN(SELECT unnest(?::VARCHAR[])) GROUP BY start)
        SELECT t.start,d.rx_max_ms,d.tx_max_ms,p.tx_dropped AS tx_dropped,
         p.tx_delayed AS tx_delayed,coalesce(r.retransmissions,0) AS retransmissions,r.point,r.frame
         FROM times t LEFT JOIN delays d USING(start) LEFT JOIN drops p USING(start) LEFT JOIN retrans r USING(start)
         ORDER BY start LIMIT 10000""",
            [hosts, hosts or topology.forward[:1]],
        )
        if hosts
        and db.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name='host_path_series'").fetchone()[
            0
        ]
        else []
    )
    boundary_refs = {}
    for item in host.get("items", []):
        for r in item["series"]:
            boundary_refs.setdefault(r["start"], []).extend(r["evidence"])
    tx_keys = {
        r["start"]: [(r["point_a"], r["fa"]), (r["point_b"], r["fb"])]
        for r in rows(
            db,
            """SELECT start,point_a,point_b,min(evidence_frame_a) AS fa,min(evidence_frame_b) AS fb FROM delivery_series
        WHERE point_a IN(SELECT unnest(?::VARCHAR[])) AND direction='reverse' GROUP BY start,point_a,point_b""",
            [hosts],
        )
    }
    for r in timeline:
        r["_keys"] = [(r.pop("point"), r.pop("frame"))] + tx_keys.get(r["start"], [])
    attach(db, timeline)
    for r in timeline:
        r["evidence"] = (r.get("evidence", []) + boundary_refs.get(r["start"], []))[:8]
    window = host.get("window")
    db.execute("""CREATE OR REPLACE VIEW cycle_details AS SELECT p.*,
        CASE WHEN NOT p.clock_aligned OR w.reason IS NOT NULL OR w.start IS NULL THEN 'unknown'
             WHEN p.request_first<w.start THEN 'before' WHEN p.request_first<w.stop THEN 'event' ELSE 'recovery' END AS period,
        w.start AS event_start,w.stop AS event_end FROM cycle_top_points p LEFT JOIN cycle_windows w USING(flow)""")
    detail = rows(db, "SELECT * FROM cycle_details")
    old = {(r["cycle_id"], r["point"]): r.get("evidence", []) for r in cycles["top"]}
    for r in detail:
        r["evidence"] = old.get((r["cycle_id"], r["point"]), [])
    cycles["top"] = detail
    for r in cycles["series"]:
        r["_keys"] = [(r["point"], r["evidence_frame"])]
    attach(db, cycles["series"])
    top_pairs = rows(
        db, """SELECT p.* FROM cycle_pairs p JOIN cycle_top t USING(cycle_id) ORDER BY t.max_ms DESC,p.hop"""
    )
    for r in top_pairs:
        r["_keys"] = [(r["point_a"], r["frame_a"]), (r["point_b"], r["frame_b"])]
    attach(db, top_pairs)
    bars = []
    for cycle_id in dict.fromkeys(r["cycle_id"] for r in detail):
        points = [r for r in detail if r["cycle_id"] == cycle_id]
        pair = [r for r in top_pairs if r["cycle_id"] == cycle_id]
        local = next((r for r in points if r["point"] in hosts), None)
        parts = [
            dict(
                name=r["hop"] + " " + r["component"],
                component=r["component"],
                ms=r["added_ms"],
                uncertainty_ms=r["uncertainty_ms"],
                reason=r["reason"],
                evidence=r["evidence"],
            )
            for r in pair
        ]
        expected = rows(db, "SELECT * FROM cycle_edges")
        known = {r["hop"] for r in pair}
        for edge in expected:
            if edge["hop"] not in known:
                parts.append(
                    dict(
                        name=edge["hop"] + " " + ("RX" if edge["direction"] == "forward" else "TX"),
                        component="RX" if edge["direction"] == "forward" else "TX",
                        ms=None,
                        uncertainty_ms=edge["uncertainty_ms"],
                        reason="No paired cycle at this edge; component unknown",
                        evidence=[
                            e for r in points if r["point"] in (edge["a"], edge["b"]) for e in r["evidence"]
                        ],
                    )
                )
        if local:
            parts.append(
                dict(
                    name="server-local",
                    component="local",
                    ms=local["turnaround_ms"] if local["reason"] is None else None,
                    uncertainty_ms=0,
                    reason=local["reason"],
                    evidence=local["evidence"],
                )
            )
        bars.append(
            dict(
                cycle_id=cycle_id,
                flow=points[0]["flow"],
                time=min(
                    (r["request_first"] for r in points if r["request_first"] is not None), default=None
                ),
                total_ms=max((r["cycle_ms"] for r in points if r["cycle_ms"] is not None), default=None),
                rx_ms=None
                if any(r["ms"] is None for r in parts if r["component"] == "RX")
                else sum(r["ms"] for r in parts if r["component"] == "RX"),
                tx_ms=None
                if any(r["ms"] is None for r in parts if r["component"] == "TX")
                else sum(r["ms"] for r in parts if r["component"] == "TX"),
                parts=parts,
            )
        )
    # Existing per-flow/port rows gain period p95s and per-hop components without replacing the engine table.
    db.execute("""CREATE OR REPLACE VIEW cycle_flow_detail AS SELECT f.*,
        p.before_p95_ms,p.event_p95_ms,p.recovery_p95_ms,p.unknown_p95_ms,h.per_hop_added
        FROM cycle_flow_ports f LEFT JOIN(
          SELECT point,flow,max(p95_ms) FILTER(WHERE period='before') AS before_p95_ms,
          max(p95_ms) FILTER(WHERE period='event') AS event_p95_ms,max(p95_ms) FILTER(WHERE period='recovery') AS recovery_p95_ms,
          max(p95_ms) FILTER(WHERE period='unknown') AS unknown_p95_ms FROM cycle_periods GROUP BY point,flow) p USING(point,flow)
        LEFT JOIN(SELECT flow,to_json(list(struct_pack(hop:=hop,component:=component,p95_ms:=p95_ms))) AS per_hop_added
          FROM(SELECT flow,hop,component,quantile_cont(added_ms,.95) AS p95_ms FROM cycle_pairs GROUP BY flow,hop,component) GROUP BY flow) h USING(flow)""")
    cycles["flow_ports"] = rows(db, "SELECT * FROM cycle_flow_detail ORDER BY max_ms DESC NULLS LAST,point,flow,port LIMIT 2000")
    quality = rows(
        db,
        """SELECT point_a,point_b,direction,start,sum(observations) AS observations,sum(dropped) AS loss,
        sum(capture_misses) AS capture_misses,sum(unknown) AS unknown FROM adjacent_match_rates GROUP BY ALL ORDER BY start,point_a,point_b LIMIT 10000""",
    )
    offload = rows(
        db,
        """SELECT e.point_a,e.point_b,e.direction,floor(e.time_a) AS start,count(DISTINCT e.key_a) AS offload_mismatch
       FROM delivery_events e JOIN obs a ON a.point=e.point_a AND a.packet_key=e.key_a
       JOIN obs b ON b.point=e.point_b AND b.packet_key=e.key_b
       WHERE e.classification='unknown' AND a.length<>b.length AND greatest(a.length,b.length)>1500 GROUP BY ALL""",
    )
    offload_index = {
        (r["point_a"], r["point_b"], r["direction"], r["start"]): r["offload_mismatch"] for r in offload
    }
    quality_refs = rows(
        db,
        """SELECT point_a,point_b,direction,start,min(evidence_frame_a) AS fa,min(evidence_frame_b) AS fb
        FROM adjacent_match_rates GROUP BY ALL""",
    )
    qr = {(r["point_a"], r["point_b"], r["direction"], r["start"]): r for r in quality_refs}
    for r in quality:
        key = tuple(r[k] for k in ("point_a", "point_b", "direction", "start"))
        r["offload_mismatch"] = min(r["unknown"], offload_index.get(key, 0))
        for name, count in [
            ("capture_miss_percent", r["capture_misses"]),
            ("loss_percent", r["loss"]),
            ("offload_mismatch_percent", r["offload_mismatch"]),
            ("unknown_percent", r["unknown"] - r["offload_mismatch"]),
        ]:
            r[name] = 100 * count / r["observations"] if r["observations"] else None
        e = qr.get(key, {})
        r["_keys"] = [(r["point_a"], e.get("fa")), (r["point_b"], e.get("fb"))]
    attach(db, quality)
    delivery_rows = rows(
        db,
        """SELECT point_a,point_b,direction,start,sum(delayed) AS delayed,sum(dropped) AS dropped,
        sum(capture_misses) AS capture_misses,sum(unknown) AS unknown,min(evidence_frame_a) AS fa,min(evidence_frame_b) AS fb
        FROM adjacent_match_rates GROUP BY ALL ORDER BY start,point_a,point_b LIMIT 10000""",
    )
    for r in delivery_rows:
        r["_keys"] = [(r["point_a"], r.pop("fa")), (r["point_b"], r.pop("fb"))]
    attach(db, delivery_rows)
    return dict(
        timeline=timeline,
        cycle_bars=bars,
        delivery=delivery_rows,
        quality=quality,
        hold_release=[f for f in findings if f["type"] == "hold_release"],
        window=window,
        headline=next((r["headline"] for r in host["items"]), "Host-path aggregate not computed"),
        loss_groups=host.get("loss_groups", []),
        scope="Saved analysis window. Each chart selection filters the shared time range; baseline and aggregate headline remain full-window.",
        quality_note="Offload mismatch means an unknown copy pair with different segmentation and a >1500-byte capture unit. Other unknowns remain separate; capture miss is supported by later/ACK evidence. Rates use observed physical pair units, not bytes. Chart rows are capped at 10,000; engine exports retain all rows.",
    )
