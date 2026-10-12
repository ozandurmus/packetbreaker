"""Bounded sequence/ACK/window points and full-population flow rate/RTT buckets."""

from .store import rows
from .topology import Topology
from .transport import prepare
from .evidence import evidence


def charts(project, flow, point=None, direction="forward", start=None, end=None, limit=2000, local=False):
    with project.connect() as db:
        report = project.get(db, "report")
        raw = project.get(db, "topology")
        if not report or not raw:
            return dict(points=[], packets=[], buckets=[], reason="Run analysis first")
        topology = Topology.model_validate(raw)
        prepare(db, project, topology, report)
        present = {
            r[0]
            for r in db.execute("SELECT DISTINCT point FROM transport_tcp WHERE flow=?", [flow]).fetchall()
        }
        points = [dict(point=p.id, label=p.label) for p in topology.points if p.id in present]
        if not points:
            return dict(points=[], packets=[], buckets=[], reason="No TCP observations for this conversation")
        point = point or points[0]["point"]
        if point not in present:
            raise ValueError("Capture point does not belong to this TCP conversation")
        model = report["clocks"][next(p.capture_id for p in topology.points if p.id == point)]
        reference = report["clocks"][
            next(p.capture_id for p in topology.points if p.id == topology.forward[0])
        ]
        aligned = model.get("offset") is not None and model.get("domain") == reference.get("domain")
        if not aligned and not local:
            start = end = None
        time_column = "corrected" if aligned else "ts"
        origin = db.execute(
            "SELECT coalesce((SELECT isn FROM transport_handshake WHERE flow=? AND point=? AND direction=?),arg_min(seq,ts)) FROM transport_tcp WHERE flow=? AND point=? AND direction=? AND length>0",
            [flow, point, direction, flow, point, direction],
        ).fetchone()[0]
        if origin is None:
            return dict(
                points=points, packets=[], buckets=[], reason="No data in this direction", point=point
            )
        handshake = db.execute(
            "SELECT handshake FROM transport_handshake WHERE flow=? AND point=? AND direction=?",
            [flow, point, direction],
        ).fetchone()
        where = f"flow=? AND point=? AND (? IS NULL OR {time_column}>=?) AND (? IS NULL OR {time_column}<?)"
        params = [flow, point, start, start, end, end]
        packet_where = (
            where.replace("flow=?", "t.flow=?")
            .replace("point=?", "t.point=?")
            .replace(time_column, "t." + time_column)
        )
        data = rows(
            db,
            f"""SELECT t.frame,t.{time_column} AS time,t.raw_seq,t.raw_ack,t.length,
            CASE WHEN t.direction=? AND t.length>0 THEN 'data' ELSE 'ack' END AS kind,
            CASE WHEN t.direction=? THEN (t.seq-?+4294967296)%4294967296 ELSE (t.ack-?+4294967296)%4294967296 END AS sequence,
            t.retrans OR t.fast_retrans OR t.spurious AS retransmission,t.out_of_order,
            w.receive_window,t.indexed,t.trusted FROM transport_tcp t LEFT JOIN transport_acks w
            ON w.flow=t.flow AND w.point=t.point AND w.frame=t.frame AND w.direction=?
            WHERE """
            + packet_where
            + """ AND ((t.direction=? AND t.length>0 AND (t.flags&2)=0)
                OR (t.direction<>? AND (t.flags&16)>0)) ORDER BY time,frame LIMIT ?""",
            [direction, direction, origin, origin, direction] + params + [direction, direction, limit],
        )
        for packet in data:
            if packet["sequence"] >= 2147483648:
                packet["sequence"] = None
            packet["window_edge"] = (
                packet["sequence"] + packet["receive_window"]
                if packet["kind"] == "ack"
                and packet["sequence"] is not None
                and packet["receive_window"] is not None
                else None
            )
            if not packet["trusted"]:
                packet["retransmission"] = None
        count = db.execute(
            "SELECT count(*) FROM transport_tcp WHERE "
            + where
            + " AND ((direction=? AND length>0 AND (flags&2)=0) OR(direction<>? AND (flags&16)>0))",
            params + [direction, direction],
        ).fetchone()[0]
        extent = db.execute(
            f"SELECT min({time_column}),max({time_column}) FROM transport_tcp WHERE " + where, params
        ).fetchone()
        capture = db.execute(
            f"SELECT min({time_column}),max({time_column}) FROM obs WHERE point=?", [point]
        ).fetchone()
        width = topology.bucket_seconds
        lo = start if start is not None else extent[0]
        hi = end if end is not None else extent[1]
        if lo is None or hi is None:
            return dict(
                points=points, packets=[], buckets=[], reason="No observations in this range", point=point
            )
        buckets = rows(
            db,
            f"""WITH b AS(SELECT floor(({time_column}-?)/?)::BIGINT AS bucket,
            sum(length*8) FILTER(WHERE direction=? AND (flags&2)=0) AS bits,
            (median(rtt) FILTER(WHERE direction<>? AND trusted))*1000 AS rtt_ms,
            arg_min(frame,{time_column}) FILTER(WHERE direction=? AND length>0) AS data_frame,
            arg_max(frame,rtt) FILTER(WHERE direction<>? AND rtt IS NOT NULL) AS rtt_frame
            FROM transport_tcp WHERE """
            + where
            + """ GROUP BY bucket), grid AS(
            SELECT unnest(range(0,least(10000,ceil((?-?)/?)::BIGINT+1))) AS bucket)
            SELECT g.bucket,?+g.bucket*? AS time,
            CASE WHEN ?+g.bucket*?>=? AND ?+(g.bucket+1)*?<=? THEN coalesce(b.bits,0)/? END AS throughput_bps,
            b.rtt_ms,b.data_frame,b.rtt_frame,
            CASE WHEN ?+g.bucket*?< ? OR ?+(g.bucket+1)*?>? THEN 'partial / not capturing' ELSE 'capturing' END AS coverage
            FROM grid g LEFT JOIN b USING(bucket) ORDER BY g.bucket""",
            [lo, width, direction, direction, direction, direction]
            + params
            + [
                hi,
                lo,
                width,
                lo,
                width,
                lo,
                width,
                max(capture[0], lo),
                lo,
                width,
                min(capture[1], hi),
                width,
                lo,
                width,
                max(capture[0], lo),
                lo,
                width,
                min(capture[1], hi),
            ],
        )
        return dict(
            points=points,
            point=point,
            direction=direction,
            aligned=aligned,
            packets=data,
            buckets=buckets,
            total=count,
            bucket_seconds=width,
            reason=None,
            clock_uncertainty_ms=model.get("uncertainty_ms"),
            note=(
                "Clock-corrected timestamps; "
                + (
                    "SYN-anchored sequence bytes."
                    if handshake and handshake[0]
                    else "Sequence origin is first observed byte; handshake/window scale unknown."
                )
            )
            if aligned
            else "Local unaligned clock: brush filters this chart point only; cross-point time comparison is unknown.",
            sampling_note=f"{len(data)} of {count} packet points shown. Rate/RTT buckets use all indexed observations; narrow the time brush for omitted packet evidence.",
        )


def frame_evidence(project, flow, point, frames):
    with project.connect() as db:
        return evidence(
            db,
            "o.flow=? AND o.point=? AND o.frame IN(SELECT unnest(?::BIGINT[]))",
            [flow, point, frames],
            len(frames),
        )
