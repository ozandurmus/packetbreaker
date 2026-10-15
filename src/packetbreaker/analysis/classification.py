from ..byte_ranges import range_ack_guard, range_condition, range_later_seen, range_recoveries
from ..device_drops import finding_context, upgrade_events
from ..evidence import evidence
from ..fragments import guard_missing
from ..store import rows


def _prepare_missing_and_recoveries(
    db, topology, a, b, direction, downstream, start, end, common_end, byte_active
):
    missing_condition = "NOT EXISTS(SELECT 1 FROM obs b WHERE b.point=? AND b.packet_key=a.packet_key AND b.eligible)"
    if byte_active:
        missing_condition = f"((NOT {range_condition()} AND {missing_condition}) OR EXISTS(SELECT 1 FROM byte_missing z WHERE z.point_a=a.point AND z.point_b='{b}' AND z.source_frame=a.frame))"
    db.execute(
        f"""CREATE OR REPLACE TEMP TABLE missing AS SELECT a.*,NULL::VARCHAR AS range_unknown,
        EXISTS(SELECT 1 FROM obs later WHERE later.packet_key=a.packet_key AND later.point IN
            (SELECT unnest(?::VARCHAR[])) AND later.eligible) AS later_seen
        FROM obs a WHERE a.point=? AND a.direction=? AND a.eligible
        AND (a.length>0 OR (a.proto='TCP' AND (a.flags&7)>0) OR a.proto IN ('UDP','ICMP'))
        AND {missing_condition}
        AND (? IS NULL OR coalesce(a.corrected,a.ts)>=?) AND (? IS NULL OR coalesce(a.corrected,a.ts)<=?)""",
        [downstream, a, direction, b, start, start, end, end],
    )
    if byte_active:
        range_later_seen(db, a, b, direction, downstream)
    guard_missing(db, b)
    # Re-delivery requires the same byte range and local stream; new IP ID is allowed.
    # ponytail: recoveries beyond 60 seconds stay unknown; extend for long-RTO investigations.
    db.execute(
        """CREATE OR REPLACE TEMP TABLE recoveries AS
        SELECT m.packet_key,min(r.corrected) AS recovery_time,arg_min(r.packet_key,r.corrected) AS recovery_key,
        count(*) AS attempts
        FROM missing m JOIN obs r ON r.point=? AND r.canon=m.canon AND r.proto='TCP'
        AND r.seq=m.seq AND r.length=m.length AND (r.flags&7)=(m.flags&7) AND r.corrected>m.corrected
        AND r.corrected<=m.corrected+60 AND r.packet_key<>m.packet_key AND r.eligible
        AND left(coalesce(r.prefix,''),least(length(coalesce(r.prefix,'')),length(coalesce(m.prefix,''))))=
            left(coalesce(m.prefix,''),least(length(coalesce(r.prefix,'')),length(coalesce(m.prefix,''))))
        WHERE EXISTS(SELECT 1 FROM obs upstream WHERE upstream.point=? AND upstream.packet_key=r.packet_key
            AND upstream.stream=m.stream AND upstream.corrected>m.corrected)
        GROUP BY m.packet_key""",
        [b, a],
    )
    db.execute("""CREATE OR REPLACE TEMP TABLE retry_counts AS
        SELECT m.packet_key,count(*) AS attempts FROM missing m JOIN recoveries r USING(packet_key)
        JOIN obs u ON u.point=m.point AND u.stream=m.stream AND u.canon=m.canon
        AND u.seq=m.seq AND u.length=m.length AND (u.flags&7)=(m.flags&7) AND u.corrected>m.corrected
        AND u.corrected<=r.recovery_time GROUP BY m.packet_key""")
    db.execute("""UPDATE recoveries SET attempts=c.attempts FROM retry_counts c
        WHERE recoveries.packet_key=c.packet_key""")
    if byte_active:
        range_recoveries(db, a, b)
    db.execute(
        """CREATE OR REPLACE TEMP TABLE acked AS
        SELECT m.packet_key,arg_min(ack.packet_key,ack.corrected) AS ack_key FROM missing m JOIN obs ack ON ack.point=? AND ack.proto='TCP'
        AND ack.stream=m.stream AND ack.canon=m.canon_reverse AND (ack.flags & 16)>0
        AND ack.corrected>m.corrected AND ack.corrected<=m.corrected+60
        AND ((ack.ack-m.seq-m.length-CASE WHEN (m.flags&3)>0 THEN 1 ELSE 0 END+4294967296)%4294967296)<2147483648
        WHERE m.proto='TCP' AND (m.length>0 OR (m.flags&3)>0) AND (m.flags&4)=0 AND NOT EXISTS(
            SELECT 1 FROM obs r WHERE r.point=m.point AND r.canon=m.canon AND r.seq=m.seq
            AND r.stream=m.stream AND r.length=m.length AND r.corrected>m.corrected AND r.corrected<ack.corrected) GROUP BY m.packet_key""",
        [a],
    )
    if byte_active:
        range_ack_guard(db, a, b)
    db.execute("""INSERT INTO acked
        SELECT m.packet_key,arg_min(reply.packet_key,reply.corrected) AS ack_key
        FROM missing m JOIN obs reply ON reply.point=m.point AND reply.proto=m.proto
        AND reply.canon=m.canon_reverse AND reply.corrected>m.corrected AND reply.corrected<=m.corrected+60
        WHERE (m.proto='UDP' AND m.dns_id IS NOT NULL AND NOT m.dns_response
               AND reply.dns_id=m.dns_id AND reply.dns_response
               AND NOT EXISTS(SELECT 1 FROM obs retry WHERE retry.point=m.point AND retry.canon=m.canon
                 AND retry.dns_id=m.dns_id AND NOT retry.dns_response AND retry.eligible
                 AND retry.corrected>m.corrected AND retry.corrected<reply.corrected))
           OR (m.proto='ICMP' AND m.icmp_type=8 AND reply.icmp_type=0
               AND m.icmp_id=reply.icmp_id AND m.icmp_seq=reply.icmp_seq
               AND NOT EXISTS(SELECT 1 FROM obs retry WHERE retry.point=m.point AND retry.canon=m.canon
                 AND retry.icmp_type=8 AND retry.icmp_id=m.icmp_id AND retry.icmp_seq=m.icmp_seq
                 AND retry.corrected>m.corrected AND retry.corrected<reply.corrected AND retry.eligible))
        GROUP BY m.packet_key""")
    # A reset can prove delivery only when it must be a reply: the resetting side had already closed
    # the connection with FIN before the missing segment, so it cannot abort on its own any more. Its
    # RST without ACK (seq = the trigger's ACK) observed at the downstream point B then proves that a
    # segment carrying that ACK got past B. A spontaneous abort by a side that still holds the
    # connection carries the same seq, so without the earlier FIN the absence stays loss evidence.
    # Each candidate trigger needs its own RST; a middlebox that drops and rejects never puts its RST
    # on the far side of B.
    db.execute(
        """INSERT INTO acked
        SELECT m.packet_key,arg_min(rst.packet_key,rst.corrected) AS ack_key
        FROM missing m JOIN obs rst ON rst.point=? AND rst.proto='TCP' AND rst.canon=m.canon_reverse
        AND (rst.flags&4)>0 AND (rst.flags&16)=0 AND rst.seq=m.ack
        AND rst.corrected>m.corrected AND rst.corrected<=m.corrected+3
        WHERE m.proto='TCP' AND (m.flags&4)=0 AND (m.flags&16)>0
        AND NOT EXISTS(SELECT 1 FROM acked x WHERE x.packet_key=m.packet_key)
        AND EXISTS(SELECT 1 FROM obs fin WHERE fin.point=rst.point AND fin.proto='TCP'
            AND fin.canon=m.canon_reverse AND (fin.flags&1)>0 AND fin.corrected<m.corrected)
        AND (SELECT count(DISTINCT r2.frame) FROM obs r2 WHERE r2.point=rst.point AND r2.proto='TCP'
            AND r2.canon=m.canon_reverse AND (r2.flags&4)>0 AND (r2.flags&16)=0 AND r2.seq=m.ack
            AND r2.corrected>m.corrected AND r2.corrected<=m.corrected+3)
          >= (SELECT count(*) FROM obs c WHERE c.point=m.point AND c.proto='TCP' AND c.canon=m.canon
            AND c.ack=m.ack AND (c.flags&4)=0 AND c.corrected>=m.corrected AND c.corrected<rst.corrected)
        GROUP BY m.packet_key""",
        [b],
    )
    db.execute(
        """CREATE OR REPLACE TEMP TABLE failures AS
        SELECT m.packet_key,min(f.corrected) AS failure_time,arg_min(f.packet_key,f.corrected) AS failure_key
        FROM missing m JOIN obs f ON f.point=m.point AND f.stream=m.stream AND f.proto='TCP'
        AND f.corrected>m.corrected AND f.corrected<=m.corrected+60 AND f.corrected<=?
        WHERE m.proto='TCP' AND ((f.flags&4)>0 OR
            (f.corrected-m.corrected>=? AND (
                (f.canon=m.canon AND f.seq=m.seq AND f.length=m.length AND (f.flags&7)=(m.flags&7)) OR
                (f.canon<>m.canon AND (f.flags&16)>0
                 AND ((m.seq+m.length-f.ack+4294967296)%4294967296) BETWEEN 1 AND 2147483647))))
        GROUP BY m.packet_key""",
        [common_end, topology.stall_ms / 1000],
    )


def _insert_segment_events(
    db,
    topology,
    segment_id,
    a,
    b,
    direction,
    classification_reason,
    common_start,
    common_end,
    byte_active,
    has_device_proofs,
    device_name,
):
    db.execute(
        f"""INSERT INTO events
        SELECT md5(? || m.packet_key),?,?,?,
        CASE WHEN later_seen THEN 'capture_miss'
            WHEN m.range_unknown IS NOT NULL THEN 'unknown'
            WHEN ? IS NOT NULL OR ? IS NULL OR m.corrected<? OR m.corrected>? THEN 'unknown'
            WHEN ack.packet_key IS NOT NULL THEN 'capture_miss'
            WHEN r.recovery_time IS NOT NULL THEN CASE WHEN (r.recovery_time-m.corrected)*1000>=? OR r.attempts>1
                THEN 'impactful_loss' ELSE 'recovered_loss' END
            WHEN m.corrected+?>? THEN 'unknown'
            WHEN (m.flags&2)>0 AND m.proto='TCP' THEN 'handshake_blocked'
            WHEN f.failure_time IS NOT NULL THEN 'impactful_loss' ELSE 'unrecovered_loss' END,
        CASE WHEN later_seen THEN 'Packet appears again farther along the path'
            WHEN m.range_unknown IS NOT NULL THEN m.range_unknown
            WHEN ? IS NOT NULL THEN ? WHEN ? IS NULL OR m.corrected<? OR m.corrected>? THEN 'Outside common coverage; absence is not proof of loss'
            WHEN ack.packet_key IS NOT NULL THEN 'Receiver ACK, downstream no-socket RST, DNS response, or echo reply proves delivery without an earlier retry'
            WHEN r.recovery_time IS NOT NULL THEN 'Original missing downstream; repeated byte range was delivered'
            WHEN m.corrected+?>? THEN 'Insufficient remaining capture coverage to assess completion'
            WHEN (m.flags&2)>0 AND m.proto='TCP' THEN 'Handshake control segment stops at this boundary; cause unknown'
            WHEN f.failure_time IS NOT NULL THEN 'Unrecovered disappearance followed by a reset or observed stall; cause unknown'
            ELSE 'Unrecovered disappearance within covered, matchable traffic; cause unknown' END,
        m.packet_key,m.flow,coalesce(m.corrected,m.ts),(r.recovery_time-m.corrected)*1000,r.recovery_key,
        coalesce(ack.ack_key,CASE WHEN r.recovery_time IS NULL THEN f.failure_key END),
        CASE WHEN r.recovery_time IS NULL THEN (f.failure_time-m.corrected)*1000 END,{"coalesce(z.missing_bytes,m.length)>0" if byte_active else "m.length>0"},
        {"coalesce(z.missing_bytes,m.length),z.byte_ranges" if byte_active else "m.length,NULL::VARCHAR"}
        FROM missing m LEFT JOIN recoveries r USING(packet_key) LEFT JOIN acked ack USING(packet_key)
        LEFT JOIN failures f USING(packet_key)
        {f"LEFT JOIN byte_missing z ON z.point_a=m.point AND z.point_b='{b}' AND z.source_frame=m.frame" if byte_active else ""}""",
        [
            segment_id,
            a,
            b,
            direction,
            classification_reason,
            common_start,
            common_start,
            common_end,
            topology.stall_ms,
            topology.stall_ms / 1000,
            common_end,
            classification_reason,
            classification_reason,
            common_start,
            common_start,
            common_end,
            topology.stall_ms / 1000,
            common_end,
        ],
    )
    if has_device_proofs:
        upgrade_events(db, a, b, direction, device_name)


def _record_class_findings_and_bytes(
    db, pa, pb, segment, segment_id, a, b, direction, classes, reason, start, end, byte_active, findings
):
    for cls in classes:
        severity = {
            "confirmed_device_drop": "high",
            "handshake_blocked": "high",
            "unrecovered_loss": "low",
            "impactful_loss": "high",
            "recovered_loss": "low",
            "capture_miss": "quality",
            "unknown": "unknown",
        }[cls["kind"]]
        event = db.execute(
            """SELECT packet_key,recovery_key,support_key FROM events WHERE point_a=? AND point_b=? AND direction=? AND kind=? ORDER BY ts LIMIT 1""",
            [a, b, direction, cls["kind"]],
        ).fetchone()
        refs = evidence(db, "o.packet_key IN (?,?,?)", list(event))
        findings.append(
            dict(
                id=f"{segment_id}:{cls['kind']}",
                type=cls["kind"],
                **(
                    finding_context(db, a, b, direction)
                    if cls["kind"] == "confirmed_device_drop"
                    else {}
                ),
                severity=severity,
                hop=segment_id,
                direction=direction,
                time_range=[cls["first_seen"], cls["last_seen"]],
                confidence="supported" if severity != "unknown" else "unknown",
                metrics=cls,
                cause="device_stage_evidence"
                if cls["kind"] == "confirmed_device_drop"
                else "unknown"
                if cls["kind"] != "capture_miss"
                else "capture_visibility",
                summary=(
                    f"Handshake blocked between {pa.label} and {pb.label}; cause unknown."
                    if cls["kind"] == "handshake_blocked"
                    else f"{cls['count']} {cls['kind'].replace('_', ' ')} event(s) between {pa.label} and {pb.label}."
                ),
                evidence=refs,
                evidence_note="First event shown; select the hop to browse all events",
            )
        )
    if byte_active:
        byte_count = db.execute(
            "SELECT coalesce(sum(length),0) FROM obs WHERE point=? AND direction=? AND eligible AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<=?)",
            [a, direction, start, start, end, end],
        ).fetchone()[0]
        lost_bytes = sum(
            x["missing_bytes"] or 0
            for x in classes
            if x["kind"] in ("recovered_loss", "impactful_loss", "unrecovered_loss")
        )
        ranged = (
            db.execute(
                "SELECT count(*) FROM obs o JOIN byte_flows f ON o.flow=f.flow AND o.direction=f.direction WHERE o.point=? AND o.direction=?",
                [a, direction],
            ).fetchone()[0]
            > 0
        )
        segment.update(
            matching_mode="byte_ranges" if ranged else "packets",
            eligible_bytes=byte_count,
            lost_bytes=lost_bytes,
            byte_loss_percent=100 * lost_bytes / byte_count
            if byte_count and not reason
            else None,
        )


def classify_segment_losses(
    db,
    topology,
    pa,
    pb,
    segment,
    segment_id,
    a,
    b,
    direction,
    downstream,
    classification_reason,
    start,
    end,
    common_start,
    common_end,
    byte_active,
    has_device_proofs,
    findings,
):
    _prepare_missing_and_recoveries(
        db, topology, a, b, direction, downstream, start, end, common_end, byte_active
    )
    _insert_segment_events(
        db,
        topology,
        segment_id,
        a,
        b,
        direction,
        classification_reason,
        common_start,
        common_end,
        byte_active,
        has_device_proofs,
        pa.device,
    )
    total = db.execute(
        """SELECT count(*) FROM obs WHERE point=? AND direction=? AND eligible
        AND (length>0 OR (proto='TCP' AND (flags&7)>0) OR proto IN ('UDP','ICMP'))
        AND (? IS NULL OR coalesce(corrected,ts)>=?) AND (? IS NULL OR coalesce(corrected,ts)<=?)""",
        [a, direction, start, start, end, end],
    ).fetchone()[0]
    classes = rows(
        db,
        """SELECT kind,count(*) AS count,sum(missing_bytes) AS missing_bytes,min(ts) AS first_seen,max(ts) AS last_seen,
        max(recovery_ms) AS max_recovery_ms,max(greatest(impact_ms,recovery_ms)) AS max_stall_ms,
        count(*) FILTER(WHERE is_data) AS data_count,
        count(*) FILTER(WHERE recovery_key IS NOT NULL) AS delivered_retries FROM events WHERE point_a=? AND point_b=? AND direction=? GROUP BY kind""",
        [a, b, direction],
    )
    segment.update(eligible_packets=total, classes={x["kind"]: x["count"] for x in classes})
    loss_count = sum(
        x["count"]
        for x in classes
        if x["kind"]
        in (
            "recovered_loss",
            "impactful_loss",
            "unrecovered_loss",
            "handshake_blocked",
            "confirmed_device_drop",
        )
    )
    reason = segment["reason"]
    if (
        pa.vendor == "checkpoint"
        and pb.device == pa.device
        and any(c["kind"] == "unknown" for c in classes)
    ):
        reason = classification_reason
        segment["reason"] = reason
    segment["loss_percent"] = 100 * loss_count / total if total and not reason else None
    _record_class_findings_and_bytes(
        db, pa, pb, segment, segment_id, a, b, direction, classes, reason, start, end, byte_active, findings
    )
