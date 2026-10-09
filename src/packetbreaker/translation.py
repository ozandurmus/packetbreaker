"""Learn declared TCP sequence translations from independent packet anchors."""

from .store import rows
from .evidence import evidence

MOD = 4294967296


def normalize_sequences(db, topology):
    db.execute("""CREATE OR REPLACE TABLE sequence_models (
        ingress VARCHAR,egress VARCHAR,point VARCHAR,old_flow VARCHAR,ingress_stream BIGINT,stream BIGINT,
        forward_offset BIGINT,reverse_offset BIGINT,boundary_forward_offset BIGINT,boundary_reverse_offset BIGINT,
        samples BIGINT,status VARCHAR,reason VARCHAR,frame_a BIGINT,frame_b BIGINT)""")
    db.execute("""CREATE OR REPLACE TEMP TABLE translation_links (
        point_a VARCHAR,stream_a BIGINT,point_b VARCHAR,stream_b BIGINT,old_flow VARCHAR)""")
    points = {p.id: p for p in topology.points}
    boundaries = [
        (a, b)
        for a, b in zip(topology.forward, topology.forward[1:])
        if points[a].device == points[b].device
        and "seq_randomization" in (points[a].translation, points[b].translation)
    ]
    paired = {p for pair in boundaries for p in pair}
    if any(p.translation == "seq_randomization" and p.id not in paired for p in topology.points):
        raise ValueError("Sequence randomization needs adjacent ingress/egress points of the same device")
    for a, b in boundaries:
        # Payload anchors tolerate changed IP IDs; ID anchors also cover constant-payload/control traffic.
        db.execute("""CREATE OR REPLACE TEMP TABLE sequence_anchors AS
            WITH widths AS (SELECT flow,direction,length,min(length(coalesce(prefix,''))) AS width
                FROM obs WHERE proto='TCP' GROUP BY flow,direction,length),
            shapes AS (SELECT o.*,md5(direction||':'||flags||':'||o.length||':'||left(coalesce(prefix,''),width)) AS shape
                FROM obs o JOIN widths USING(flow,direction,length) WHERE proto='TCP' AND stream>=0),
            keys AS (SELECT *, 'payload:'||shape AS key FROM shapes WHERE length(prefix)>=16
                UNION ALL SELECT *, 'id:'||ipid||':'||shape AS key FROM shapes)
            SELECT * FROM keys QUALIFY count(*) OVER(PARTITION BY point,flow,key)=1""")
        model_rows = []
        for target in dict.fromkeys(topology.forward + topology.reverse):
            if target == a:
                continue
            db.execute(
                f"""CREATE OR REPLACE TEMP TABLE sequence_pairs AS
                SELECT DISTINCT x.flow,x.stream AS sa,y.stream AS sb,x.frame AS fa,y.frame AS fb,x.direction,
                    (y.raw_seq-x.seq+{MOD})%{MOD} AS seq_delta,
                    CASE WHEN (x.flags&16)>0 THEN (y.raw_ack-x.ack+{MOD})%{MOD} END AS ack_delta,
                    (y.raw_seq-x.raw_seq+{MOD})%{MOD} AS raw_seq_delta,
                    CASE WHEN (x.flags&16)>0 THEN (y.raw_ack-x.raw_ack+{MOD})%{MOD} END AS raw_ack_delta,
                    y.ts-x.ts AS dt
                FROM sequence_anchors x JOIN sequence_anchors y ON x.flow=y.flow AND x.key=y.key
                WHERE x.point=? AND y.point=?""",
                [a, target],
            )
            found = rows(
                db,
                """WITH deltas AS (
                SELECT *,CASE WHEN direction='forward' THEN seq_delta ELSE ack_delta END AS f,
                    CASE WHEN direction='reverse' THEN seq_delta ELSE ack_delta END AS r,
                    CASE WHEN direction='forward' THEN raw_seq_delta ELSE raw_ack_delta END AS raw_f,
                    CASE WHEN direction='reverse' THEN raw_seq_delta ELSE raw_ack_delta END AS raw_r
                FROM sequence_pairs)
                SELECT flow,sa,sb,count(*) AS n,min(f) AS f,max(f) AS f_max,min(r) AS r,max(r) AS r_max,
                    count(f) AS nf,count(r) AS nr,min(raw_f) AS raw_f,min(raw_r) AS raw_r,
                    max(dt)-min(dt) AS spread,min(fa) AS fa,arg_min(fb,fa) AS fb
                FROM deltas GROUP BY flow,sa,sb""",
            )
            counts_a = {}
            counts_b = {}
            for row in found:
                if row["n"] >= 3:
                    counts_a[(row["flow"], row["sa"])] = counts_a.get((row["flow"], row["sa"]), 0) + 1
                    counts_b[(row["flow"], row["sb"])] = counts_b.get((row["flow"], row["sb"]), 0) + 1
            for row in found:
                reason = None
                if row["n"] < 3 or min(row["nf"], row["nr"]) < 2:
                    reason = "Insufficient independent sequence-translation anchors"
                elif (
                    counts_a.get((row["flow"], row["sa"])) != 1 or counts_b.get((row["flow"], row["sb"])) != 1
                ):
                    reason = "Ambiguous TCP session correspondence at sequence translation"
                elif row["f"] != row["f_max"] or row["r"] != row["r_max"]:
                    reason = "Inconsistent sequence/ACK offset within this flow"
                elif row["spread"] > topology.match_window_ms / 1000:
                    reason = "Sequence-anchor timing exceeds the match window"
                model_rows.append(
                    [
                        a,
                        b,
                        target,
                        row["flow"],
                        row["sa"],
                        row["sb"],
                        row["f"],
                        row["r"],
                        row["raw_f"],
                        row["raw_r"],
                        row["n"],
                        "unknown" if reason else "learned",
                        reason,
                        row["fa"],
                        row["fb"],
                    ]
                )
                if (
                    row["n"] >= 3
                    and counts_a.get((row["flow"], row["sa"])) == 1
                    and counts_b.get((row["flow"], row["sb"])) == 1
                ):
                    db.execute(
                        "INSERT INTO translation_links VALUES (?,?,?,?,?)",
                        [a, row["sa"], target, row["sb"], row["flow"]],
                    )
        if model_rows:
            db.executemany("INSERT INTO sequence_models VALUES (" + ",".join("?" * 15) + ")", model_rows)
        # No silent unsupported boundary: each unpaired local session gets an explicit unknown result.
        for point in (a, b):
            for flow, stream, frame in db.execute(
                "SELECT flow,stream,min(frame) FROM obs WHERE point=? AND proto='TCP' GROUP BY flow,stream",
                [point],
            ).fetchall():
                column = "ingress_stream" if point == a else "stream"
                if not db.execute(
                    f"SELECT count(*) FROM sequence_models WHERE ingress=? AND point=? AND old_flow=? AND {column}=?",
                    [a, b, flow, stream],
                ).fetchone()[0]:
                    db.execute(
                        "INSERT INTO sequence_models VALUES (" + ",".join("?" * 15) + ")",
                        [
                            a,
                            b,
                            b,
                            flow,
                            stream if point == a else -1,
                            stream if point == b else -1,
                            None,
                            None,
                            None,
                            None,
                            0,
                            "unknown",
                            "Insufficient independent sequence-translation anchors",
                            frame if point == a else None,
                            frame if point == b else None,
                        ],
                    )
        db.execute(
            """CREATE OR REPLACE TEMP TABLE bad_sequence_sessions AS
            SELECT old_flow,ingress_stream,min(reason) AS reason FROM sequence_models
            WHERE ingress=? AND point=? AND status='unknown' GROUP BY old_flow,ingress_stream""",
            [a, b],
        )
        db.execute(
            """UPDATE sequence_models SET status='unknown',reason=bad.reason
            FROM bad_sequence_sessions bad WHERE ingress=? AND sequence_models.old_flow=bad.old_flow
            AND sequence_models.ingress_stream=bad.ingress_stream""",
            [a],
        )
        maps = []
        for m in rows(db, "SELECT * FROM sequence_models WHERE ingress=?", [a]):
            maps.append(
                (
                    m["point"],
                    m["old_flow"],
                    m["stream"],
                    m["forward_offset"],
                    m["reverse_offset"],
                    m["point"] in topology.forward[topology.forward.index(b) :],
                    m["reason"],
                )
            )
            if m["ingress_stream"] >= 0:
                maps.append(
                    (
                        a,
                        m["old_flow"],
                        m["ingress_stream"],
                        0,
                        0,
                        False,
                        m["reason"] if m["point"] == b else None,
                    )
                )
        db.execute(
            "CREATE OR REPLACE TEMP TABLE sequence_map(point VARCHAR,old_flow VARCHAR,stream BIGINT,f BIGINT,r BIGINT,apply_offset BOOLEAN,reason VARCHAR)"
        )
        if maps:
            db.executemany("INSERT INTO sequence_map VALUES (?,?,?,?,?,?,?)", list(set(maps)))
        db.execute("""CREATE OR REPLACE TEMP TABLE sequence_map AS SELECT point,old_flow,stream,
            min(f) AS f,min(r) AS r,bool_or(apply_offset) AS apply_offset,max(reason) AS reason FROM sequence_map GROUP BY point,old_flow,stream""")
        db.execute(f"""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
            CASE WHEN m.apply_offset AND m.reason IS NULL THEN (o.raw_seq-CASE WHEN direction='forward' THEN m.f ELSE m.r END+{MOD})%{MOD} ELSE o.seq END AS seq,
            CASE WHEN m.apply_offset AND m.reason IS NULL AND (flags&16)>0 THEN (o.raw_ack-CASE WHEN direction='forward' THEN m.r ELSE m.f END+{MOD})%{MOD} ELSE o.ack END AS ack,
            coalesce(nullif(o.unsupported,''),m.reason) AS unsupported,coalesce(o.translation_reason,m.reason) AS translation_reason)
            FROM obs o LEFT JOIN sequence_map m ON o.point=m.point AND o.flow=m.old_flow AND o.stream=m.stream""")
        db.execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
            CASE WHEN m.point IS NOT NULL THEN md5(proto||':'||ipid||':'||seq||':'||ack||':'||flags||':'||length) ELSE signature END AS signature)
            FROM obs o LEFT JOIN sequence_map m ON o.point=m.point AND o.flow=m.old_flow AND o.stream=m.stream""")
        db.execute("UPDATE obs SET packet_key=md5(canon||signature)")


def sequence_report(db):
    result = rows(
        db,
        """SELECT m.*,arg_min(o.flow,o.frame) AS flow FROM sequence_models m
        LEFT JOIN obs o ON o.point=m.ingress AND o.stream=m.ingress_stream
        WHERE m.point=m.egress GROUP BY ALL ORDER BY m.ingress,m.ingress_stream LIMIT 200""",
    )
    for model in result:
        model["evidence"] = evidence(
            db,
            "(o.point=? AND o.frame=?) OR (o.point=? AND o.frame=?)",
            [model["ingress"], model["frame_a"], model["egress"], model["frame_b"]],
            4,
        )
    return result
