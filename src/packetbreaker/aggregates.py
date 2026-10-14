"""Stable reference metrics over existing engine tables; no additional matching."""

from .store import rows
from .incident import attach


def add_aggregates(db, topology, segments, hosts, cycles, onsets, models, byte_active):
    window = hosts.get("window")
    if window and window.get("status") == "unknown":
        window = None
    scopes = {
        "analysis": (topology.start, topology.end),
        "event": (window["start"], window["end"]) if window else None,
    }
    points = {p.id: p for p in topology.points}
    boundary = [s for s in segments if points[s["point_a"]].host_capture != points[s["point_b"]].host_capture]
    db.execute("CREATE OR REPLACE TEMP TABLE aggregate_boundaries(hop VARCHAR,host VARCHAR)")
    if boundary:
        db.executemany(
            "INSERT INTO aggregate_boundaries VALUES (?,?)",
            [
                (s["id"], s["point_a"] if points[s["point_a"]].host_capture else s["point_b"])
                for s in boundary
            ],
        )
    db.execute("""CREATE OR REPLACE TEMP TABLE aggregate_cycles AS SELECT cycle_id,min(flow) AS flow,min(port) AS port,
        min(request_first) FILTER(WHERE clock_aligned) AS time,bool_or(stalled) AS stalled
        FROM cycle_points WHERE reason IS NULL GROUP BY cycle_id""")
    db.execute("""CREATE OR REPLACE TEMP TABLE aggregate_added AS SELECT p.cycle_id,p.flow,p.port,e.host,min(p.time) AS time,
        sum(greatest(0,p.added_ms)) FILTER(WHERE component='RX') AS rx_ms,
        sum(greatest(0,p.added_ms)) FILTER(WHERE component='TX') AS tx_ms,
        sum(greatest(0,p.added_ms)) AS added_ms,sum(p.uncertainty_ms) AS uncertainty_ms,
        list(struct_pack(point_a:=p.point_a,point_b:=p.point_b,frame_a:=p.frame_a,frame_b:=p.frame_b)) AS frames
        FROM cycle_pairs p JOIN aggregate_boundaries e USING(hop) GROUP BY p.cycle_id,p.flow,p.port,e.host
        HAVING count(*)=2 AND count(DISTINCT component)=2 AND bool_and(p.reason IS NULL AND p.added_ms IS NOT NULL)""")
    atom_sql = (
        """SELECT point,flow,direction,lo,hi,source_frame AS frame,corrected AS time FROM byte_obs
        WHERE is_atom AND eligible AND kind='data' UNION ALL """
        if byte_active
        else ""
    )
    ordinary = """SELECT point,flow,direction,seq AS lo,seq+length AS hi,frame,corrected AS time FROM obs
        WHERE proto='TCP' AND length>0 AND eligible"""
    if byte_active:
        ordinary += (
            " AND NOT EXISTS(SELECT 1 FROM byte_flows b WHERE b.flow=obs.flow AND b.direction=obs.direction)"
        )
    db.execute("CREATE OR REPLACE TEMP TABLE aggregate_copies AS " + atom_sql + ordinary)
    host_points = [p for p in topology.points if p.host_capture]
    db.execute(
        "CREATE OR REPLACE TEMP TABLE aggregate_host_clocks(point VARCHAR,capture_id VARCHAR,epoch DOUBLE,offset_s DOUBLE,drift DOUBLE)"
    )
    for p in host_points:
        m = models[p.capture_id]
        db.execute(
            "INSERT INTO aggregate_host_clocks VALUES (?,?,?,?,?)",
            [p.id, p.capture_id, m.epoch, m.offset, m.drift],
        )
    db.execute("""CREATE OR REPLACE TEMP TABLE aggregate_host_packets AS SELECT c.point,p.frame,
        c.epoch+(p.ts-c.epoch-c.offset_s)/(1+c.drift) AS time
        FROM packets p JOIN aggregate_host_clocks c USING(capture_id)""")
    selected = [p.id for p in host_points] or topology.forward[:1]
    for scope, bounds in scopes.items():
        if bounds is None:
            cycles[scope] = dict(
                total=None,
                stalled_total=None,
                max_added_ms=None,
                repeat_groups={"forward": None, "reverse": None},
                reason="No supported global event window",
            )
            hosts[scope] = dict(rx_share=None, max_silence_ms=None, reason="No supported global event window")
            onsets[scope] = dict(
                retrans_peak_time=None, retrans_peak_count=None, reason="No supported global event window"
            )
            continue
        start, end = bounds
        predicate = "(? IS NULL OR time>=?) AND (? IS NULL OR time<?)"
        params = [start, start, end, end]
        # Whole-analysis local cycles remain countable when their global clock is unknown.
        counts = db.execute(
            "SELECT count(*),count(*) FILTER(WHERE stalled) FROM aggregate_cycles"
            + (" WHERE " + predicate if scope == "event" else ""),
            params if scope == "event" else [],
        ).fetchone()
        c = dict(total=counts[0], stalled_total=counts[1], stall_ms=topology.cycle_stall_ms)
        best = rows(
            db,
            "SELECT * FROM aggregate_added WHERE " + predicate + " ORDER BY added_ms DESC,cycle_id LIMIT 1",
            params,
        )
        if best:
            best = best[0]
            best["_keys"] = [
                (p, f)
                for r in best["frames"]
                for p, f in [(r["point_a"], r["frame_a"]), (r["point_b"], r["frame_b"])]
            ]
            attach(db, [best])
            c["max_added_ms"] = best["added_ms"]
            c["max_added"] = best
        else:
            c.update(
                max_added_ms=None,
                max_added=None,
                max_added_reason="No complete clock-valid RX + TX boundary pair for a cycle",
            )
        repeats = rows(
            db,
            """SELECT direction,count(*) AS groups FROM(
            SELECT DISTINCT flow,direction,lo,hi FROM aggregate_copies GROUP BY point,flow,direction,lo,hi
            HAVING count(DISTINCT frame)>1"""
            + (" AND count(*) FILTER(WHERE " + predicate + ")>0" if scope == "event" else "")
            + ") GROUP BY direction",
            params if scope == "event" else [],
        )
        c["repeat_groups"] = {
            d: next((r["groups"] for r in repeats if r["direction"] == d), 0) for d in ("forward", "reverse")
        }
        cycles[scope] = c
        rx, total = db.execute(
            "SELECT sum(rx_ms),sum(added_ms) FROM aggregate_added WHERE " + predicate, params
        ).fetchone()
        h = dict(
            rx_share=100 * rx / total if total else None,
            rx_share_reason=None if total else "No positive complete cycle-added delay",
            silence=[],
        )
        for p in host_points:
            coverage = db.execute(
                "SELECT min(time),max(time),count(time) FROM aggregate_host_packets WHERE point=?", [p.id]
            ).fetchone()
            # A silence observation cannot distinguish no traffic from an unreported capture outage.
            if start is None or end is None or not coverage[2] or coverage[0] > start or coverage[1] < end:
                h["silence"].append(
                    dict(
                        point=p.id,
                        max_silence_ms=None,
                        reason="Clock or coverage does not bracket the requested window",
                        evidence=[],
                    )
                )
                continue
            gap = rows(
                db,
                """WITH ordered AS(SELECT frame,time,lag(time) OVER(ORDER BY time,frame) AS previous,
                lag(frame) OVER(ORDER BY time,frame) AS previous_frame FROM aggregate_host_packets WHERE point=?)
                SELECT (least(time,?)-greatest(previous,?))*1000 AS max_silence_ms,
                greatest(previous,?) AS start,least(time,?) AS "end",frame,previous_frame FROM ordered
                WHERE previous IS NOT NULL AND previous<? AND time>? ORDER BY max_silence_ms DESC,previous LIMIT 1""",
                [p.id, end, start, start, end, end, start],
            )
            g = gap[0] if gap else dict(max_silence_ms=None, reason="No bracketing packet pair")
            g.update(point=p.id, _keys=[(p.id, g.get("previous_frame")), (p.id, g.get("frame"))])
            attach(db, [g])
            h["silence"].append(g)
        h["max_silence_ms"] = (
            max((r["max_silence_ms"] for r in h["silence"]), default=None)
            if h["silence"] and all(r["max_silence_ms"] is not None for r in h["silence"])
            else None
        )
        h["silence_note"] = (
            "All valid host capture frames, including unrelated flows. Observed silence is not proof of a stall or capture continuity."
        )
        hosts[scope] = h
        peak = rows(
            db,
            """SELECT point,floor(corrected) AS time,count(*) AS count,min(frame) AS frame FROM obs
            WHERE retrans AND eligible AND corrected IS NOT NULL AND point IN(SELECT unnest(?::VARCHAR[]))
            AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?) GROUP BY point,floor(corrected)
            ORDER BY count DESC,time,point LIMIT 1""",
            [selected, *params],
        )
        if peak:
            peak = peak[0]
            peak["_keys"] = [(peak["point"], peak["frame"])]
            attach(db, [peak])
            onsets[scope] = dict(
                retrans_peak_time=peak["time"], retrans_peak_count=peak["count"], retrans_peak=peak
            )
        else:
            unknown = db.execute(
                "SELECT count(*) FROM obs WHERE retrans AND corrected IS NULL AND point IN(SELECT unnest(?::VARCHAR[]))",
                [selected],
            ).fetchone()[0]
            onsets[scope] = dict(
                retrans_peak_time=None,
                retrans_peak_count=None if unknown else 0,
                reason="Retransmission clock unknown" if unknown else "No retransmissions observed in scope",
            )
        for item in hosts["items"]:
            n = db.execute(
                "SELECT count(DISTINCT flow) FROM host_transit WHERE direction=? AND reason IS NULL AND delay_ms>=? AND "
                + predicate,
                [item["direction"], topology.cycle_stall_ms, *params],
            ).fetchone()[0]
            item["affected_flows_ge_stall" + ("_event" if scope == "event" else "")] = n
    for key in ("total", "stalled_total", "max_added_ms", "max_added", "repeat_groups"):
        cycles[key] = cycles["analysis"].get(key)
    hosts["rx_share"] = hosts["analysis"].get("rx_share")
    hosts["max_silence_ms"] = hosts["event"].get("max_silence_ms")
    for key in ("retrans_peak_time", "retrans_peak_count", "retrans_peak"):
        onsets[key] = onsets["analysis"].get(key)
    for item in hosts["items"]:
        if scopes["event"] is None:
            item["affected_flows_ge_stall_event"] = None
    cycles["aggregate_note"] = (
        "Distinct measured cycle IDs, stalled if any measured point reaches stall_ms. Added time requires both clock-valid host-boundary RX/TX components; positive components include recovery wait. Repeat groups deduplicate capture points and ignore SPAN copies; offload uses canonical byte ranges."
    )
