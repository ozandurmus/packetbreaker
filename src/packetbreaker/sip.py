"""Compare tshark SIP/SDP messages and bind media by uniquely advertised source endpoints."""

from .store import rows
from .udp_index import protocol_evidence as evidence, frame_evidence
from .rtp import media_finding

NOTE = "SIP message identity includes canonical signaling flow, Call-ID, CSeq, status and direction. Only unique bounded pairs are compared. Declared ALG rewriting is expected, not a bug. Media association requires a unique SDP source endpoint; ports or SSRC alone cannot identify a call. SDP/media mismatch is corroboration, not proof of a policy cause."
FIELDS = ("sdp.connection_info.address", "sdp.media.port", "sip.Contact", "sip.Via")


def build_sip(db, topology, segments, clocks, rtp_findings):
    db.execute("""CREATE OR REPLACE TABLE sip_messages AS SELECT o.*,d."sip.Call-ID" AS call_id,
        d."sip.CSeq.seq" AS cseq,d."sip.CSeq.method" AS method,coalesce(d."sip.Status-Code",'request') AS status,
        d."sdp.connection_info.address" AS address,try_cast(d."sdp.media.port" AS INTEGER) AS port,
        d."sdp.media_attr" AS attributes,d."sdp.media.media" AS media,d."sip.Contact" AS contact,d."sip.Via" AS via,
        o.eligible AND o.caplen=o.wirelen AND c.reason IS NULL AND NOT contains(d."sip.CSeq.seq",',') AS complete
        FROM obs o JOIN udp_decoded d USING(point,frame) JOIN udp_decode_cache c USING(point)
        WHERE d."sip.Call-ID" IS NOT NULL""")
    if not db.execute("SELECT 1 FROM sip_messages LIMIT 1").fetchone():
        db.execute("DROP TABLE IF EXISTS rtp_call_packets")
        return dict(comparisons=[], total=0, one_way=[], note=NOTE, scope="Full saved analysis window"), []
    points = {p.id: p for p in topology.points}
    comparisons = []
    findings = []
    for segment in segments:
        a, b = segment["point_a"], segment["point_b"]
        messages = rows(
            db,
            """WITH candidates AS(SELECT x.frame,y.frame AS frame_b,y.corrected AS time_b,
            y.address AS address_b,y.port AS port_b,y.contact AS contact_b,y.via AS via_b,
            count(*) OVER(PARTITION BY y.frame) AS owners
            FROM sip_messages x JOIN sip_messages y ON x.flow=y.flow AND x.call_id=y.call_id AND x.cseq=y.cseq
            AND x.method=y.method AND x.status=y.status AND x.direction=y.direction
            WHERE x.point=? AND y.point=? AND x.direction=? AND x.complete AND y.complete
            AND abs(y.corrected-x.corrected)<=?), pairs AS(SELECT frame,count(*) AS candidates,bool_or(owners<>1) AS ambiguous,
            min(frame_b) AS frame_b,min(address_b) AS address_b,min(port_b) AS port_b,min(contact_b) AS contact_b,min(via_b) AS via_b
            FROM candidates GROUP BY frame)
            SELECT x.call_id,x.flow,x.direction,x.corrected AS time,x.frame,x.address,x.port,x.contact,x.via,
            p.* EXCLUDE(frame) FROM sip_messages x LEFT JOIN pairs p USING(frame) WHERE x.point=? AND x.direction=? AND (? IS NULL OR x.corrected>=?) AND (? IS NULL OR x.corrected<=?)""",
            [
                a,
                b,
                segment["direction"],
                topology.match_window_ms / 1000,
                a,
                segment["direction"],
                topology.start,
                topology.start,
                topology.end,
                topology.end,
            ],
        )
        refs_by_frame = frame_evidence(
            db,
            [
                (point, frame)
                for message in messages
                for point, frame in ((a, message["frame"]), (b, message["frame_b"]))
            ],
        )
        reliable = not segment.get("reason") and all(
            clocks.get(points[p].capture_id, {}).get("uncertainty") is not None for p in (a, b)
        )
        for message in messages:
            supported = reliable and message["candidates"] == 1 and not message["ambiguous"]
            changes = {
                field: dict(before=message[key], after=message[key + "_b"])
                for field, key in zip(FIELDS, ("address", "port", "contact", "via"))
                if supported and message[key] != message[key + "_b"]
            }
            expected = bool(
                segment.get("device") and any(points[p].payload_transform == "alg" for p in (a, b))
            )
            refs = [
                refs_by_frame[(point, frame)]
                for point, frame in ((a, message["frame"]), (b, message["frame_b"] if supported else None))
                if (point, frame) in refs_by_frame
            ]
            item = dict(
                call_id=message["call_id"],
                flow=message["flow"],
                hop=segment["id"],
                device=segment.get("device"),
                direction=segment["direction"],
                changes=changes,
                status="expected rewriting"
                if changes and expected
                else "undeclared rewriting"
                if changes
                else "unchanged"
                if supported
                else "unknown",
                reason="Unique message and reliable segment"
                if supported
                else "Ambiguous/missing message, incomplete coverage, translation or clock evidence",
                evidence=refs,
                tooltip=NOTE,
            )
            comparisons.append(item)
            if not changes:
                continue
            if not expected:
                name = segment.get("device") or f"link between {points[a].label} and {points[b].label}"
                f = media_finding(
                    db,
                    "sip_rewritten",
                    segment,
                    message["time"],
                    f"SIP rewritten by {name} (not declared)",
                    dict(call_id=message["call_id"], flow=message["flow"], changes=changes),
                    refs,
                )
                f["tooltip"] = NOTE
                findings.append(f)
            # The peer sees the rewritten advertisement, and the actual arriving source tuple.
            if not any(field.startswith("sdp.") for field in changes):
                continue
            peer = (
                topology.forward[-1]
                if message["direction"] == "forward"
                else topology.reverse[-1]
                if topology.reverse
                else None
            )
            # Filled after endpoint association below.
            item["_mismatch"] = dict(message=message, segment=segment, peer=peer)
    # Earliest sending-side SDP of each role anchors media source identity before NAT.
    db.execute(
        """CREATE OR REPLACE TEMP TABLE sip_endpoints AS SELECT call_id,flow AS signaling_flow,direction,address,port,corrected AS time,
        attributes,point,frame FROM sip_messages WHERE complete AND media='audio' AND port>0 AND address IS NOT NULL AND NOT contains(address,',')
        AND (direction='forward' AND point=? OR direction='reverse' AND point=?)
        QUALIFY row_number() OVER(PARTITION BY flow,call_id,direction ORDER BY corrected,frame)=1""",
        [topology.forward[0], topology.reverse[0] if topology.reverse else None],
    )
    db.execute("""CREATE OR REPLACE TABLE rtp_call_packets AS WITH c AS(SELECT r.*,s.call_id,s.signaling_flow,
        count(*) OVER(PARTITION BY r.point,r.frame) AS owners FROM rtp_input r JOIN sip_endpoints s
        ON r.direction=s.direction AND json_extract_string(r.canon,'$[1]')=s.address AND try_cast(json_extract_string(r.canon,'$[2]') AS INTEGER)=s.port
        AND r.corrected>=s.time AND r.corrected<=s.time+300)
        SELECT * FROM c WHERE owners=1""")
    for item in comparisons:
        pending = item.pop("_mismatch", None)
        if not pending:
            continue
        message, segment, peer = pending["message"], pending["segment"], pending["peer"]
        media = rows(
            db,
            """SELECT DISTINCT src,sport,flow,min(frame) AS frame FROM rtp_call_packets WHERE call_id=? AND signaling_flow=? AND direction=? AND point=? GROUP BY ALL""",
            [message["call_id"], message["flow"], message["direction"], peer],
        )
        if len(media) != 1:
            item["media_status"] = "unknown"
            item["media_reason"] = "No unique actual media source at receiving endpoint"
            continue
        m = media[0]
        mismatch = (message["address_b"], message["port_b"]) != (m["src"], m["sport"])
        item["media_status"] = "mismatch" if mismatch else "matches actual RTP source"
        if mismatch:
            name = (
                segment.get("device")
                or f"link between {points[segment['point_a']].label} and {points[segment['point_b']].label}"
            )
            refs = item["evidence"] + evidence(db, "o.point=? AND o.frame=?", [peer, m["frame"]], 1)
            f = media_finding(
                db,
                "sdp_media_mismatch",
                segment,
                message["time"],
                f"SDP / media mismatch at {name}",
                dict(
                    call_id=message["call_id"],
                    flow=message["flow"],
                    advertised_address=message["address_b"],
                    advertised_port=message["port_b"],
                    actual_address=m["src"],
                    actual_port=m["sport"],
                ),
                refs,
            )
            f["tooltip"] = NOTE
            findings.append(f)
    one_way = []
    calls = rows(
        db,
        """SELECT call_id,signaling_flow FROM sip_endpoints GROUP BY ALL HAVING count(DISTINCT direction)=2
        AND bool_and(NOT coalesce(attributes LIKE '%sendonly%' OR attributes LIKE '%recvonly%' OR attributes LIKE '%inactive%',false))""",
    )
    for call in calls:
        observed = rows(
            db,
            """SELECT point,direction,flow,min(corrected) AS time,min(frame) AS frame FROM rtp_call_packets
            WHERE call_id=? AND signaling_flow=? GROUP BY ALL""",
            [call["call_id"], call["signaling_flow"]],
        )
        for direction, path in [("forward", topology.forward), ("reverse", topology.reverse)]:
            if not path:
                continue
            if not any(r["point"] == path[0] and r["direction"] == direction for r in observed):
                continue
            if any(r["point"] == path[-1] and r["direction"] == direction for r in observed):
                continue
            opposite = "reverse" if direction == "forward" else "forward"
            if not any(r["point"] == path[-1] and r["direction"] == opposite for r in observed):
                continue
            source_flows = {r["flow"] for r in observed if r["direction"] == direction}
            losses = [
                f
                for f in rtp_findings
                if f["type"] == "rtp_loss"
                and f["direction"] == direction
                and f["metrics"]["flow"] in source_flows
            ]
            if not losses:
                continue
            loss = losses[0]
            segment = next(s for s in segments if s["id"] == loss["hop"])
            if segment.get("reason") or any(
                clocks.get(points[p].capture_id, {}).get("uncertainty") is None
                for p in (segment["point_a"], segment["point_b"])
            ):
                continue
            mismatch = any(
                f["type"] == "sdp_media_mismatch"
                and f["metrics"]["call_id"] == call["call_id"]
                and f["metrics"]["flow"] == call["signaling_flow"]
                for f in findings
            )
            reason = (
                "Wrong SDP advertisement corroborated by actual media tuple"
                if mismatch
                else "Return media stops at a supported disappearance hop; device policy cause unknown"
            )
            refs = loss["evidence"] + evidence(
                db,
                "o.point=? AND o.frame IN (SELECT frame FROM sip_endpoints WHERE call_id=? AND signaling_flow=?)",
                [path[0], call["call_id"], call["signaling_flow"]],
                2,
            )
            f = media_finding(
                db,
                "one_way_audio",
                segment,
                loss["time_range"][0],
                f"One-way audio: {direction} media stops between {points[segment['point_a']].label} and {points[segment['point_b']].label}",
                dict(call_id=call["call_id"], flow=loss["metrics"]["flow"], reason=reason),
                refs,
            )
            f["tooltip"] = NOTE
            findings.append(f)
            one_way.append(
                dict(call_id=call["call_id"], hop=loss["hop"], reason=reason, evidence=refs, tooltip=NOTE)
            )
    return dict(
        comparisons=comparisons[:200],
        total=len(comparisons),
        one_way=one_way,
        note=NOTE,
        scope="Selected-window comparisons; earlier SDP provides context; up to 200 comparisons; single SDP media section only",
    ), findings
