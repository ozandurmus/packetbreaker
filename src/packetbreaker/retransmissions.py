"""tshark TCP recovery subtypes and matched-pair reordering origin."""

from .store import rows
from .evidence import evidence

RETRY_KIND = """CASE WHEN NOT trusted OR NOT indexed THEN 'unknown'
    WHEN spurious AND delivered THEN 'spurious'
    WHEN sack_hole AND fast_retrans AND duplicate_acks>=2 THEN 'sack'
    WHEN fast_retrans THEN 'fast'
    WHEN rto_seconds>=rto_bound AND prior_rtts>=3 AND duplicate_acks=0 AND NOT sack_hole THEN 'rto'
    ELSE 'unknown' END"""
REASONS = {
    "unknown": "Recovery mechanism unknown: missing trustworthy timer/ACK/SACK evidence",
    "fast": "tshark fast retransmission at this independently decoded point",
    "sack": "tshark fast retransmission after duplicate ACKs with a SACK block beyond the retransmitted hole",
    "spurious": "tshark spurious flag corroborated by an earlier cumulative ACK covering these bytes",
    "rto": "RTO-compatible retry: tshark retry interval exceeds a conservative 1 s / prior RTT+4 sigma timer bound, without observed duplicate-ACK/SACK trigger; actual socket timer is not observable",
}


def prepare(db):
    db.execute("""CREATE OR REPLACE TABLE transport_retry_signals AS
        SELECT r.*,s.relative_seq,s.seq_end,h.prior_rtts,greatest(1,coalesce(h.prior_median+4*h.variation,1)) AS rto_bound,
        coalesce(a.delivered,false) AS delivered,coalesce(a.sack_hole,false) AS sack_hole,coalesce(a.duplicate_acks,0) AS duplicate_acks,a.ack_trigger_frame,a.delivered_frame
        FROM transport_tcp r LEFT JOIN transport_samples s ON r.point=s.point AND r.flow=s.flow AND r.frame=s.frame
        LEFT JOIN LATERAL(SELECT count(*) AS prior_rtts,median(rtt) AS prior_median,stddev_pop(rtt) AS variation
            FROM transport_acks t WHERE t.flow=r.flow AND t.point=r.point AND t.direction=r.direction AND t.ts<r.ts AND t.rtt IS NOT NULL) h ON true
        LEFT JOIN LATERAL(SELECT bool_or(t.ack_end>=s.seq_end) AS delivered,
            bool_or(t.sack_left IS NOT NULL AND (t.sack_left-r.raw_seq+4294967296)%4294967296 BETWEEN 1 AND 2147483647
                AND t.ack_end<=s.relative_seq) AS sack_hole,
            count(*) FILTER(WHERE t.duplicate_ack AND t.ts>=r.ts-.05) AS duplicate_acks,
            arg_max(t.frame,t.ts) FILTER(WHERE t.duplicate_ack OR t.sack_left IS NOT NULL) AS ack_trigger_frame,
            arg_min(t.frame,t.ts) FILTER(WHERE t.ack_end>=s.seq_end) AS delivered_frame
            FROM transport_acks t WHERE t.flow=r.flow AND t.point=r.point AND t.direction=r.direction AND t.ts<r.ts
            AND t.ts>=r.ts-greatest(.05,coalesce(r.rto_seconds,0))) a ON true
        WHERE r.retrans OR r.fast_retrans OR r.spurious""")
    db.execute(
        "CREATE OR REPLACE TABLE transport_retries AS SELECT *,"
        + RETRY_KIND
        + " AS retry_kind FROM transport_retry_signals"
    )
    db.execute("""CREATE OR REPLACE TEMP TABLE transport_order_neighbors AS SELECT *,
        lead(packet_key) OVER(PARTITION BY flow,point,direction ORDER BY relative_seq,ts,frame) AS next_key,
        lead(ts) OVER(PARTITION BY flow,point,direction ORDER BY relative_seq,ts,frame) AS next_ts
        FROM transport_samples WHERE eligible AND trusted AND indexed AND handshake AND NOT retrans AND NOT spurious""")
    db.execute("""CREATE OR REPLACE TABLE transport_reordering AS
        SELECT a.flow,e.direction,e.hop,a.point,a.frame,b.point AS downstream,b.frame AS downstream_frame,
        c.frame AS neighbor_frame,d.frame AS downstream_neighbor_frame,b.corrected AS time,
        'Original matched byte ranges changed arrival order across this edge; tshark out-of-order downstream and in order upstream' AS reason
        FROM transport_edges e JOIN transport_order_neighbors a ON a.point=e.a AND a.direction=e.direction AND NOT a.out_of_order
        JOIN transport_tcp b ON b.point=e.b AND b.flow=a.flow AND b.packet_key=a.packet_key AND b.out_of_order AND b.trusted AND b.indexed AND b.eligible
        JOIN transport_tcp c ON c.point=e.a AND c.flow=a.flow AND c.packet_key=a.next_key AND c.direction=a.direction
        JOIN transport_tcp d ON d.point=e.b AND d.flow=a.flow AND d.packet_key=a.next_key AND d.direction=a.direction AND d.trusted AND d.indexed AND d.eligible
        WHERE a.ts<c.ts AND b.ts>d.ts AND b.ts-d.ts<2
        QUALIFY row_number() OVER(PARTITION BY a.flow,e.direction,a.packet_key ORDER BY b.corrected,e.hop)=1""")


def report(db, topology, flow=None):
    points = rows(
        db,
        """SELECT t.flow,t.point,t.direction,bool_and(t.trusted AND t.indexed) AS usable,
        count(*) FILTER(WHERE t.duplicate_ack) AS duplicate_acks,
        count(*) FILTER(WHERE r.retry_kind='rto') AS rto,
        count(*) FILTER(WHERE r.retry_kind='fast') AS fast,
        count(*) FILTER(WHERE r.retry_kind='spurious') AS spurious,
        count(*) FILTER(WHERE r.retry_kind='sack') AS sack,
        count(*) FILTER(WHERE r.retry_kind='unknown') AS unknown
        FROM transport_tcp t LEFT JOIN transport_retries r ON t.point=r.point AND t.flow=r.flow AND t.frame=r.frame
        WHERE (? IS NULL OR t.flow=?) GROUP BY t.flow,t.point,t.direction ORDER BY t.flow,t.point,t.direction""",
        [flow, flow],
    )
    ack_counts = {
        (r["flow"], r["point"], r["direction"]): r["n"]
        for r in rows(
            db,
            """SELECT flow,point,CASE WHEN direction='forward' THEN 'reverse' ELSE 'forward' END AS direction,count(*) AS n
        FROM transport_tcp WHERE duplicate_ack GROUP BY ALL""",
        )
    }
    for p in points:
        p["duplicate_acks"] = ack_counts.get((p["flow"], p["point"], p["direction"]), 0)
        if not p["usable"]:
            for key in ("duplicate_acks", "rto", "fast", "spurious", "sack", "unknown"):
                p[key] = None
        p["tooltip"] = (
            "Mutually exclusive recovery counts at one capture point. RTO is timer-compatible, not a measured kernel timer. Retransmission here can be a sender symptom of downstream loss."
        )
        p["reason"] = None if p["usable"] else "Missing independently decoded TCP state/index; counts unknown"
    segments = []
    for p in points:
        for edge in db.execute(
            "SELECT hop FROM transport_edges WHERE a=? AND direction=?", [p["point"], p["direction"]]
        ).fetchall():
            segments.append({**p, "hop": edge[0]})
    events = rows(
        db,
        """SELECT flow,point,frame,rto_frame,retry_kind,rto_seconds,rto_bound,prior_rtts,duplicate_acks,sack_hole,ack_trigger_frame,delivered_frame FROM transport_retries
        WHERE trusted AND indexed AND (? IS NULL OR flow=?) ORDER BY ts,point,frame LIMIT 200""",
        [flow, flow],
    )
    for event in events:
        event["reason"] = REASONS[event["retry_kind"]]
        event["evidence"] = evidence(
            db,
            "o.point=? AND o.flow=? AND o.frame IN (?,?,?,?)",
            [
                event["point"],
                event["flow"],
                event["frame"],
                event["rto_frame"],
                event["ack_trigger_frame"],
                event["delivered_frame"],
            ],
            4,
        )
    reorder = rows(
        db,
        "SELECT * FROM transport_reordering WHERE (? IS NULL OR flow=?) ORDER BY time,hop LIMIT 200",
        [flow, flow],
    )
    pmap = {p.id: p for p in topology.points}
    for r in reorder:
        a, b = pmap[r["point"]], pmap[r["downstream"]]
        r["device"] = a.device if a.device == b.device else None
        r["location"] = a.device if r["device"] else f"link between {a.label} and {b.label}"
        r["confidence"] = "supported"
        r["tooltip"] = (
            r["reason"] + "; first observed order reversal, not proof of device policy or an unseen queue"
        )
        r["evidence"] = evidence(
            db,
            "o.flow=? AND ((o.point=? AND o.frame IN (?,?)) OR (o.point=? AND o.frame IN (?,?)))",
            [
                r["flow"],
                r["point"],
                r["frame"],
                r["neighbor_frame"],
                r["downstream"],
                r["downstream_frame"],
                r["downstream_neighbor_frame"],
            ],
            4,
        )
    return dict(
        points=points,
        segments=segments,
        events=events,
        reordering=reorder,
        note="Counts describe observations; repeated observation at several points is not several sender retries. Unsupported timer mechanisms remain unknown.",
    )
