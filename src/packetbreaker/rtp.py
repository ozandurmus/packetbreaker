"""RTP header accounting and RFC 3550 jitter, in native SQL on scoped streams."""

from .store import rows
from .udp_index import protocol_evidence as evidence, frame_evidence

NOTE = "Sequence gaps are observations, not automatically network loss. Streams are scoped by canonical directional tuple and SSRC, never SSRC/port alone. RFC 3550 jitter uses arrival order and a declared/SDP/static payload clock; absent or changing clocks stay unknown. Hop attribution requires independently supported matching, clocks and coverage."


def media_finding(db, kind, segment, ts, summary, metrics, refs, supported=True):
    return dict(
        id=f"media:{kind}:{segment['id']}:{metrics.get('flow', '')}:{metrics.get('call_id', '')}:{ts}",
        type=kind,
        hop=segment["id"],
        device=segment.get("device"),
        direction=segment["direction"],
        time_range=[ts, ts],
        severity="low" if supported else "unknown",
        confidence="supported" if supported else "unknown",
        summary=summary,
        headline=summary,
        metrics={"count": 1, **metrics},
        evidence=refs,
        tooltip=NOTE,
        cause="unknown",
    )


def build_rtp(db, topology, segments, clocks):
    rate = topology.rtp_clock_rate
    db.execute("""CREATE OR REPLACE TEMP TABLE rtp_sdp_rates AS SELECT point,
        try_cast("sdp.media.port" AS INTEGER) AS port,try_cast(regexp_extract("sdp.media_attr",'rtpmap:[0-9]+ [^/ ]+/([0-9]+)',1) AS INTEGER) AS rate,
        try_cast(regexp_extract("sdp.media_attr",'rtpmap:([0-9]+)',1) AS INTEGER) AS pt
        FROM udp_decoded WHERE "sdp.media.port" IS NOT NULL AND NOT contains("sdp.media.port",',')""")
    db.execute(
        """CREATE OR REPLACE TEMP TABLE rtp_rates AS SELECT point,port,pt,min(rate) AS rate FROM rtp_sdp_rates GROUP BY point,port,pt HAVING count(DISTINCT rate)=1"""
    )
    db.execute(
        """CREATE OR REPLACE TABLE rtp_input AS SELECT o.point,o.capture_id,o.frame,o.flow,o.canon,o.direction,o.ts,o.corrected,o.packet_key,o.src,o.dst,o.sport,o.dport,o.eligible,
        try_cast(d."rtp.ssrc" AS BIGINT) AS ssrc,try_cast(d."rtp.seq" AS BIGINT) AS seq,try_cast(d."rtp.timestamp" AS BIGINT) AS stamp,
        try_cast(d."rtp.p_type" AS INTEGER) AS pt,
        coalesce(?,r.rate,CASE WHEN d."rtp.p_type" IN ('0','8','13') THEN 8000 END) AS rate
        FROM obs o JOIN udp_decoded d USING(point,frame) LEFT JOIN LATERAL(SELECT min(rate) AS rate FROM rtp_rates r WHERE r.point=o.point AND r.pt=try_cast(d."rtp.p_type" AS INTEGER)
        AND r.port IN(o.sport,o.dport) HAVING count(DISTINCT rate)=1) r ON true WHERE d."rtp.version"='2' AND d."rtp.ssrc" IS NOT NULL AND (? IS NULL OR o.corrected>=?) AND (? IS NULL OR o.corrected<=?)""",
        [rate, topology.start, topology.start, topology.end, topology.end],
    )
    if not db.execute("SELECT 1 FROM rtp_input LIMIT 1").fetchone():
        db.execute("DROP TABLE IF EXISTS rtp_packets")
        db.execute("DROP TABLE IF EXISTS rtp_streams")
        return dict(streams=[], one_way=[], total=0, note=NOTE, scope="Full saved analysis window"), []
    db.execute("""CREATE OR REPLACE TEMP TABLE rtp_order AS SELECT *,row_number() OVER w AS rn,
        lag(seq) OVER w AS previous_seq,lag(stamp) OVER w AS previous_stamp,lag(ts) OVER w AS previous_ts
        FROM rtp_input WHERE eligible WINDOW w AS(PARTITION BY point,flow,direction,ssrc ORDER BY ts,frame)""")
    db.execute("""CREATE OR REPLACE TEMP TABLE rtp_spans AS WITH d AS(
        SELECT *,((seq-previous_seq+98304)%65536)-32768 AS ds,
        ((stamp-previous_stamp+6442450944)%4294967296)-2147483648 AS dt
        FROM rtp_order)
        SELECT *,first_value(seq) OVER w+coalesce(sum(ds) OVER w,0) AS extended_seq,
        abs((ts-previous_ts)*rate-dt)/16 AS innovation,
        floor((rn-1)/512)::BIGINT AS block,((rn-1)%512)+1 AS pos FROM d
        WINDOW w AS(PARTITION BY point,flow,direction,ssrc ORDER BY rn)""")
    db.execute("""CREATE OR REPLACE TEMP TABLE rtp_local AS SELECT *,
        pow(0.9375,pos)*sum(coalesce(innovation,0)/pow(0.9375,pos)) OVER(PARTITION BY point,flow,direction,ssrc,block ORDER BY rn) AS local_j,
        row_number() OVER(PARTITION BY point,flow,direction,ssrc,extended_seq ORDER BY rn) AS occurrence,
        max(extended_seq) OVER(PARTITION BY point,flow,direction,ssrc ORDER BY rn ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS prior_high
        FROM rtp_spans""")
    db.execute("""CREATE OR REPLACE TEMP TABLE rtp_blocks AS SELECT point,flow,direction,ssrc,block,max(pos) AS n,
        arg_max(local_j,rn) AS tail FROM rtp_local GROUP BY ALL""")
    db.execute("""CREATE OR REPLACE TEMP TABLE rtp_block_state AS WITH RECURSIVE state AS(
        SELECT *,0.0::DOUBLE AS previous_j,tail::DOUBLE AS final_j FROM rtp_blocks WHERE block=0
        UNION ALL SELECT b.*,s.final_j,b.tail+pow(0.9375,b.n)*s.final_j FROM rtp_blocks b JOIN state s
        ON b.point=s.point AND b.flow=s.flow AND b.direction=s.direction AND b.ssrc=s.ssrc AND b.block=s.block+1)
        SELECT * FROM state""")
    db.execute("""CREATE OR REPLACE TABLE rtp_packets AS SELECT l.*,
        CASE WHEN rate IS NOT NULL THEN (local_j+pow(0.9375,pos)*s.previous_j)/rate*1000 END AS jitter_ms
        FROM rtp_local l JOIN rtp_block_state s USING(point,flow,direction,ssrc,block)""")
    db.execute("""CREATE OR REPLACE TABLE rtp_streams AS SELECT point,flow,direction,ssrc,min(ts) AS start,max(ts) AS finish,
        count(*) AS packets,count(*)-count(DISTINCT extended_seq) AS duplicates,
        count(*) FILTER(WHERE occurrence=1 AND extended_seq<prior_high) AS reordered,
        max(extended_seq)-min(extended_seq)+1-count(DISTINCT extended_seq) AS gaps,
        count(*) FILTER(WHERE abs(ds)>3000) AS discontinuities,count(DISTINCT rate) AS clock_variants,min(rate) AS rate,
        CASE WHEN count(DISTINCT rate)=1 AND count(*) FILTER(WHERE abs(ds)>3000)=0 THEN quantile_cont(jitter_ms,.95) END AS jitter_p95_ms,
        CASE WHEN count(DISTINCT rate)=1 AND count(*) FILTER(WHERE abs(ds)>3000)=0 THEN max(jitter_ms) END AS jitter_max_ms,
        arg_min(frame,ts) AS first_frame,arg_max(frame,ts) AS last_frame FROM rtp_packets GROUP BY ALL""")
    streams = rows(db, "SELECT * FROM rtp_streams ORDER BY point,flow,direction,ssrc LIMIT 200")
    refs_by_frame = frame_evidence(
        db, [(s["point"], f) for s in streams for f in (s["first_frame"], s["last_frame"])]
    )
    for stream in streams:
        stream["tooltip"] = NOTE
        stream["reason"] = (
            "Observed header sequence range; late packets and duplicates are counted separately"
            if not stream["discontinuities"]
            else "Sequence discontinuity/restart is unknown; no loss estimate"
        )
        if stream["discontinuities"]:
            stream["gaps"] = None
        if stream["rate"] is None:
            stream["reason"] += "; clock rate unknown (no matching SDP, static payload rate or override)"
        stream["evidence"] = [
            refs_by_frame[(stream["point"], f)]
            for f in dict.fromkeys((stream["first_frame"], stream["last_frame"]))
            if (stream["point"], f) in refs_by_frame
        ]
    points = {p.id: p for p in topology.points}
    findings = []
    for segment in segments:
        a, b, d = segment["point_a"], segment["point_b"], segment["direction"]
        if segment.get("reason") or any(
            clocks.get(points[p].capture_id, {}).get("uncertainty") is None for p in (a, b)
        ):
            continue
        losses = rows(
            db,
            """SELECT r.flow,r.ssrc,count(*) AS missing,min(e.ts) AS time,arg_min(e.packet_key,e.ts) AS packet_key
            FROM events e JOIN rtp_input r ON r.point=e.point_a AND r.packet_key=e.packet_key
            WHERE e.point_a=? AND e.point_b=? AND e.direction=? AND e.kind IN('unrecovered_loss','impactful_loss','recovered_loss','confirmed_device_drop')
            GROUP BY r.flow,r.ssrc""",
            [a, b, d],
        )
        for loss in losses:
            refs = evidence(db, "o.packet_key=?", [loss["packet_key"]], 16)
            findings.append(
                media_finding(
                    db,
                    "rtp_loss",
                    segment,
                    loss["time"],
                    f"RTP datagram loss between {points[a].label} and {points[b].label}; {loss['missing']} supported missing packets for this directional stream",
                    loss,
                    refs,
                )
            )
        db.execute(
            """CREATE OR REPLACE TEMP TABLE rtp_transit AS SELECT x.flow,x.ssrc,x.seq,x.stamp,x.frame AS frame_a,y.frame AS frame_b,
            m.time_a AS time,(m.time_b-m.time_a)*1000 AS transit_ms,
            lag((m.time_b-m.time_a)*1000) OVER(PARTITION BY x.flow,x.ssrc ORDER BY m.time_a) AS previous_transit
            FROM observation_matches m JOIN rtp_input x ON x.point=m.point_a AND x.packet_key=m.key_a
            JOIN rtp_input y ON y.point=m.point_b AND y.packet_key=m.key_b AND x.ssrc=y.ssrc AND x.seq=y.seq AND x.stamp=y.stamp
            WHERE m.point_a=? AND m.point_b=? AND m.direction=?""",
            [a, b, d],
        )
        threshold = topology.rtp_jitter_ms + 2 * (segment.get("offset_uncertainty_ms") or 0)
        signals = rows(
            db,
            """SELECT flow,ssrc,count(*) FILTER(WHERE abs(transit_ms-previous_transit)>?) AS crossings,
            quantile_cont(abs(transit_ms-previous_transit),.95) AS added_variation_p95_ms,
            min(time) FILTER(WHERE abs(transit_ms-previous_transit)>?) AS time,
            arg_max(frame_a,abs(transit_ms-previous_transit)) AS frame_a,arg_max(frame_b,abs(transit_ms-previous_transit)) AS frame_b
            FROM rtp_transit GROUP BY flow,ssrc HAVING count(*) FILTER(WHERE abs(transit_ms-previous_transit)>?)>=3""",
            [threshold, threshold, threshold],
        )
        for signal in signals:
            refs = evidence(
                db,
                "(o.point=? AND o.frame=?) OR(o.point=? AND o.frame=?)",
                [a, signal["frame_a"], b, signal["frame_b"]],
                2,
            )
            findings.append(
                media_finding(
                    db,
                    "rtp_jitter",
                    segment,
                    signal["time"],
                    f"RTP transit variation first added at {segment.get('device') or 'link between ' + points[a].label + ' and ' + points[b].label}; downstream jitter is an observation, not server blame",
                    {**signal, "threshold_ms": threshold},
                    refs,
                )
            )
    one_way = rows(
        db,
        """SELECT point,flow,count(DISTINCT direction) AS directions,min(direction) AS seen_direction,
        sum(packets) AS packets FROM rtp_streams GROUP BY point,flow HAVING count(DISTINCT direction)=1""",
    )
    for item in one_way:
        item["status"] = "unknown"
        item["reason"] = (
            "Only one media direction at this point; opposite-leg or SDP expectation not established"
        )
        opposite = "reverse" if item["seen_direction"] == "forward" else "forward"
        losses = [
            f
            for f in findings
            if f["type"] == "rtp_loss" and f["direction"] == opposite and f["metrics"]["flow"] == item["flow"]
        ]
        item["stopping_hop"] = losses[0]["hop"] if losses else None
        item["evidence"] = evidence(db, "o.point=? AND o.flow=?", [item["point"], item["flow"]], 2)
        if losses:
            item["evidence"] += losses[0]["evidence"]
    return dict(
        streams=streams,
        one_way=one_way,
        total=db.execute("SELECT count(*) FROM rtp_streams").fetchone()[0],
        note=NOTE,
        scope="Selected window; jitter starts at the first sample; up to 200 stream examples",
    ), findings
