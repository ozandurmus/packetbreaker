"""Positive vendor-stage evidence, persisted for all frames with bounded display refs."""

import json

from .evidence import evidence
from .store import rows

KIND = "confirmed_device_drop"


def prepare_proofs(db, topology, start, end):
    db.execute("""CREATE OR REPLACE TABLE device_proofs (
        proof_id VARCHAR,point VARCHAR,device VARCHAR,stage VARCHAR,adapter VARCHAR,
        capture_id VARCHAR,frame BIGINT,flow VARCHAR,packet_key VARCHAR,path_key VARCHAR,
        time DOUBLE,time_source VARCHAR,status VARCHAR,reason VARCHAR,event_id VARCHAR)""")
    if not any(
        (p.vendor == "checkpoint" and p.vendor_stage == "i")
        or (p.vendor == "paloalto" and p.vendor_stage == "drop")
        for p in topology.points
    ):
        return False
    db.execute(
        "CREATE OR REPLACE TEMP TABLE vendor_points(point VARCHAR,device VARCHAR,stage VARCHAR,in_path BOOLEAN)"
    )
    used = set(topology.forward + topology.reverse)
    db.executemany(
        "INSERT INTO vendor_points VALUES (?,?,?,?)",
        [(p.id, p.device, p.vendor_stage, p.id in used) for p in topology.points],
    )
    for p in topology.points:
        if p.vendor == "checkpoint" and p.vendor_stage == "i" and p.id in used:
            downstream = [
                b
                for b in topology.points
                if b.vendor == "checkpoint"
                and b.device == p.device
                and b.capture_id == p.capture_id
                and b.id in used
                and b.vendor_stage != "i"
            ]
            inv = json.loads(
                db.execute("SELECT inventory FROM captures WHERE id=?", [p.capture_id]).fetchone()[0]
            )
            complete = (
                not any(x.translation == "full_proxy" for x in topology.points if x.device == p.device)
                and p.inspection_complete
                and {"I", "o"} <= {b.vendor_stage for b in downstream}
                and not (
                    inv.get("damaged_tail")
                    or inv.get("zero_tail_bytes")
                    or inv.get("timestamp_excluded_counts")
                    or inv.get("ifdrop")
                    or inv.get("osdrop")
                )
            )
            node_ids = {x.id for x in topology.points if x.device == p.device}
            has_nat = any(x.translation == "nat" for x in topology.points if x.id in node_ids)
            confirmed_tuples = set()
            for mapping in topology.nat_mappings:
                if mapping.point_a in node_ids and mapping.point_b in node_ids:
                    for key in (mapping.tuple_a, mapping.tuple_b):
                        confirmed_tuples.add(key)
                        proto, src, sport, dst, dport = json.loads(key)
                        confirmed_tuples.add(
                            json.dumps([proto, dst, dport, src, sport], separators=(",", ":"))
                        )
            db.execute(
                """CREATE OR REPLACE TEMP TABLE inspection_candidates AS
                SELECT o.*,EXISTS(SELECT 1 FROM obs b WHERE b.base_key=o.base_key
                    AND b.point IN (SELECT unnest(?::VARCHAR[])) AND NOT EXISTS(
                        SELECT 1 FROM obs i WHERE i.point=o.point AND i.packet_key=b.packet_key AND i.eligible)) AS unpaired_later,
                    (NOT ? OR o.tuple_key IN (SELECT unnest(?::VARCHAR[]))) AS translation_known
                FROM obs o WHERE point=? AND eligible AND NOT EXISTS (
                    SELECT 1 FROM obs b WHERE b.packet_key=o.packet_key AND b.point IN (SELECT unnest(?::VARCHAR[])))""",
                [
                    [x.id for x in downstream],
                    has_nat,
                    sorted(confirmed_tuples),
                    p.id,
                    [x.id for x in downstream],
                ],
            )
            db.execute(
                """INSERT INTO device_proofs
                SELECT point||':'||frame,point,?,'i → no I/o','checkpoint',capture_id,frame,flow,packet_key,packet_key,
                coalesce(corrected,ts),CASE WHEN corrected IS NULL THEN 'observed; inspection clock unaligned' ELSE 'corrected inspection clock' END,
                CASE WHEN supported THEN 'confirmed_device_drop' ELSE 'unknown' END,
                CASE WHEN unpaired_later THEN 'Unpaired later-stage appearance with the same identity; matching window insufficient'
                  WHEN NOT translation_known THEN 'NAT mapping not confirmed for this inspection tuple'
                  WHEN supported THEN 'Complete mapped inspection capture: i appearance has no later inspection appearance'
                  ELSE 'Inspection coverage incomplete, not attested or boundary unsupported; cannot confirm a device drop' END,NULL
                FROM (SELECT *,? AND ts+?<=? AND NOT unpaired_later AND translation_known AS supported FROM inspection_candidates)""",
                [p.device, complete, topology.match_window_ms / 1000, inv.get("end")],
            )
        elif p.vendor == "paloalto" and p.vendor_stage == "drop":
            db.execute(
                """INSERT INTO device_proofs SELECT point||':'||frame,point,?,'drop','paloalto',capture_id,frame,
                flow,packet_key,NULL,coalesce(corrected,ts),CASE WHEN corrected IS NULL THEN 'observed; clock unaligned' ELSE 'corrected' END,
                'confirmed_device_drop','Positive Palo Alto drop-stage capture (user file tag)',NULL FROM obs WHERE point=?""",
                [p.device, p.id],
            )
    # A unique positive identity can associate an auxiliary drop file without guessing a clock offset.
    db.execute("""UPDATE device_proofs p SET path_key=m.packet_key,flow=m.flow,
        time=CASE WHEN p.time_source='observed; clock unaligned' THEN coalesce(m.ts,p.time) ELSE p.time END,
        time_source=CASE WHEN p.time_source='observed; clock unaligned' AND m.ts IS NOT NULL THEN 'matched upstream timestamp; stage clock unaligned' ELSE p.time_source END
        FROM (SELECT p.proof_id,min(o.packet_key) AS packet_key,min(o.flow) AS flow,min(o.corrected) AS ts
          FROM device_proofs p JOIN obs d ON d.point=p.point AND d.frame=p.frame
          JOIN obs o ON o.base_key=d.base_key AND o.eligible
          JOIN vendor_points vp ON vp.point=o.point AND vp.device=p.device AND vp.in_path AND coalesce(vp.stage,'')<>'drop'
          WHERE p.adapter='paloalto' GROUP BY p.proof_id
          HAVING count(DISTINCT o.packet_key)=1 AND count(DISTINCT o.flow)=1) m WHERE m.proof_id=p.proof_id""")
    db.execute(
        "DELETE FROM device_proofs WHERE (? IS NOT NULL AND time<?) OR (? IS NOT NULL AND time>?)",
        [start, start, end, end],
    )

    return bool(db.execute("SELECT count(*) FROM device_proofs").fetchone()[0])


def upgrade_events(db, a, b, direction, device):
    db.execute(
        """CREATE OR REPLACE TEMP TABLE device_assignments AS
        SELECT e.id AS event_id,p.proof_id FROM events e JOIN device_proofs p ON p.path_key=e.packet_key
        WHERE e.point_a=? AND e.point_b=? AND e.direction=? AND p.device=?
          AND p.status='confirmed_device_drop' AND p.event_id IS NULL AND e.kind<>'capture_miss'
        QUALIFY row_number() OVER(PARTITION BY e.id ORDER BY p.frame,p.proof_id)=1
          AND row_number() OVER(PARTITION BY p.proof_id ORDER BY e.ts,e.id)=1""",
        [a, b, direction, device],
    )
    db.execute("""UPDATE events e SET kind='confirmed_device_drop',reason=p.reason,support_key=p.packet_key
        FROM device_assignments x JOIN device_proofs p USING(proof_id) WHERE e.id=x.event_id""")
    db.execute(
        "UPDATE device_proofs SET event_id=x.event_id FROM device_assignments x WHERE device_proofs.proof_id=x.proof_id"
    )


def finding_context(db, a, b, direction):
    facts = rows(
        db,
        """SELECT DISTINCT p.device,p.stage,p.time_source FROM device_proofs p JOIN events e ON p.event_id=e.id
                       WHERE e.point_a=? AND e.point_b=? AND e.direction=?""",
        [a, b, direction],
    )
    return dict(
        device=", ".join(sorted({f["device"] for f in facts})),
        evidence_stage=", ".join(sorted({f["stage"] for f in facts})),
        evidence_time_source=", ".join(sorted({f["time_source"] for f in facts})),
    )


def add_unplaced(db, topology, segments, findings):
    db.execute("""INSERT INTO events SELECT 'device:'||p.proof_id,p.point,p.point,o.direction,
        'confirmed_device_drop',p.reason,coalesce(p.path_key,p.packet_key),p.flow,p.time,NULL,NULL,p.packet_key,NULL,
        o.length>0,o.length,NULL FROM device_proofs p JOIN obs o ON o.point=p.point AND o.frame=p.frame
        WHERE p.status='confirmed_device_drop' AND p.event_id IS NULL""")
    db.execute(
        "UPDATE device_proofs SET event_id='device:'||proof_id WHERE status='confirmed_device_drop' AND event_id IS NULL"
    )
    groups = rows(
        db,
        """SELECT point_a,direction,count(*) AS count,sum(missing_bytes) AS missing_bytes,
        min(ts) AS first_seen,max(ts) AS last_seen FROM events WHERE point_a=point_b AND kind='confirmed_device_drop'
        GROUP BY point_a,direction""",
    )
    points = {p.id: p for p in topology.points}
    for g in groups:
        p = points[g["point_a"]]
        sid = f"{g['direction']}:{p.id}:{p.id}"
        context = finding_context(db, p.id, p.id, g["direction"])
        segments.append(
            dict(
                id=sid,
                point_a=p.id,
                point_b=p.id,
                device=p.device,
                label=p.device + " · " + str(p.vendor_stage),
                direction=g["direction"],
                location="device_stage",
                eligible_ratio=None,
                excluded_counts={},
                endpoint_quality={},
                eligible_packets=0,
                classes={KIND: g["count"]},
                loss_percent=None,
                matched=0,
                min_ms=None,
                p50_ms=None,
                p95_ms=None,
                max_ms=None,
                latency_confidence="unknown",
                offset_uncertainty_ms=None,
                reason="Positive device-stage evidence; no comparable upstream loss-rate denominator",
            )
        )
        frame = db.execute(
            """SELECT p.point,p.frame FROM device_proofs p JOIN events e ON p.event_id=e.id
                              WHERE e.point_a=? AND e.point_b=? AND e.direction=? ORDER BY e.ts,p.frame LIMIT 1""",
            [p.id, p.id, g["direction"]],
        ).fetchone()
        findings.append(
            dict(
                id=sid + ":" + KIND,
                type=KIND,
                severity="high",
                hop=sid,
                direction=g["direction"],
                time_range=[g["first_seen"], g["last_seen"]],
                metrics=g,
                confidence="supported",
                cause="device_stage_evidence",
                summary=f"{g['count']} confirmed device drop observations at {p.device}; evidence stage {context['evidence_stage']}.",
                evidence=evidence(db, "o.point=? AND o.frame=?", list(frame), 1),
                evidence_note="First positive stage observation; browse device-stage events for all frames",
                **context,
            )
        )


def device_report(db):
    sample = rows(db, "SELECT * FROM device_proofs ORDER BY time,proof_id LIMIT 200")
    if sample:
        selected = " OR ".join("(o.point=? AND o.frame=?)" for _ in sample)
        refs = evidence(
            db,
            selected,
            [v for p in sample for v in (p["point"], p["frame"])],
            len(sample),
            _expand_ranges=False,
        )
        lookup = {(r["point"], r["frame"]): r for r in refs}
        for p in sample:
            p["evidence"] = [lookup[(p["point"], p["frame"])]] if (p["point"], p["frame"]) in lookup else []
    grouped = rows(
        db,
        """SELECT device,stage,count(*) AS count FROM device_proofs
                         WHERE status='confirmed_device_drop' GROUP BY device,stage ORDER BY device,stage""",
    )
    return dict(
        vendor_device_events=sample,
        vendor_device_event_count=db.execute("SELECT count(*) FROM device_proofs").fetchone()[0],
        confirmed_device_drops=grouped,
        confirmed_device_drop_count=sum(x["count"] for x in grouped),
    )
