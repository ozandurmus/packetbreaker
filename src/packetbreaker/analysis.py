import ipaddress
import json
from datetime import datetime, timezone

from .clock import ClockModel, fit_clock
from .ingest import tuple_id
from .store import rows
from .topology import Topology


def reverse_tuple(key):
    proto, src, sport, dst, dport = json.loads(key)
    return tuple_id(proto, dst, dport, src, sport)


def evidence(db, predicate, params, limit=128):
    return rows(
        db,
        f"""SELECT o.point, c.name AS file, o.capture_id, o.frame,
        'frame.number == ' || o.frame AS display_filter, o.ts AS observed_time, o.corrected AS corrected_time
        FROM obs o JOIN captures c ON c.id=o.capture_id WHERE {predicate}
        ORDER BY o.corrected NULLS LAST,o.point,o.frame LIMIT {int(limit)}""",
        params,
    )


def prepare(db, topology):
    db.execute("DROP TABLE IF EXISTS obs")
    db.execute(
        "CREATE TABLE obs AS SELECT *, NULL::VARCHAR AS point, NULL::VARCHAR AS canon FROM packets WHERE false"
    )
    ready = {r[0] for r in db.execute("SELECT id FROM captures WHERE state='ready'").fetchall()}
    used = set(topology.forward + (topology.reverse or list(reversed(topology.forward))))
    for point in topology.points:
        if point.id not in used:
            continue
        if point.capture_id not in ready:
            raise ValueError(f"{point.label}: capture is not ready")
        clause, params = "capture_id=?", [point.capture_id]
        if point.interface is not None:
            inv = json.loads(
                db.execute("SELECT inventory FROM captures WHERE id=?", [point.capture_id]).fetchone()[0]
            )
            if inv.get("multiple_sections"):
                raise ValueError(
                    "Interface IDs repeat across pcapng sections; split sections before assigning interface filters"
                )
            clause += " AND iface=?"
            params.append(point.interface)
        if point.source_cidr:
            network = ipaddress.ip_network(point.source_cidr, strict=False)
            db.create_function(
                "point_source",
                lambda value: bool(value) and ipaddress.ip_address(value) in network,
                ["VARCHAR"],
                "BOOLEAN",
            )
            clause += " AND point_source(src)"
        db.execute(f"INSERT INTO obs SELECT *,?,tuple_key FROM packets WHERE {clause}", [point.id, *params])
        if point.source_cidr:
            db.remove_function("point_source")
    db.execute("ALTER TABLE obs ADD COLUMN corrected DOUBLE")
    db.execute("ALTER TABLE obs ADD COLUMN direction VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN packet_key VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN flow VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN eligible BOOLEAN DEFAULT false")
    # A single frame selected by two points cannot prove transit between them.
    duplicates = db.execute("""SELECT count(*) FROM (SELECT capture_id,frame FROM obs
        GROUP BY capture_id,frame HAVING count(*)>1)""").fetchone()[0]
    if duplicates:
        raise ValueError("Capture-point selections overlap: use distinct file/interface/source filters")
    db.execute("""CREATE OR REPLACE TEMP TABLE nat_candidates AS
        SELECT *,md5(signature || left(prefix,16)) AS nat_key FROM obs
        WHERE coalesce(unsupported,'')='' AND length(prefix)>=16
        QUALIFY count(*) OVER(PARTITION BY point,nat_key)=1""")
    suggestions = []
    points = {p.id: p for p in topology.points}
    for a, b in zip(topology.forward, topology.forward[1:]):
        pa, pb = points[a], points[b]
        if pa.device != pb.device or "nat" not in (pa.translation, pb.translation):
            continue
        found = rows(
            db,
            """SELECT a.tuple_key AS tuple_a,b.tuple_key AS tuple_b,count(*) AS samples,
            min(b.ts-a.ts) AS min_delta,max(b.ts-a.ts) AS max_delta,min(a.frame) AS frame_a,min(b.frame) AS frame_b
            FROM nat_candidates a JOIN nat_candidates b ON a.nat_key=b.nat_key
            AND left(a.prefix,least(length(a.prefix),length(b.prefix)))=left(b.prefix,least(length(a.prefix),length(b.prefix)))
            WHERE a.point=? AND b.point=? AND a.tuple_key<>b.tuple_key
            GROUP BY a.tuple_key,b.tuple_key HAVING count(*)>=3 AND max(b.ts-a.ts)-min(b.ts-a.ts)<1
            ORDER BY samples DESC LIMIT 1000""",
            [a, b],
        )
        for item in found:
            if sum(x["tuple_a"] == item["tuple_a"] or x["tuple_b"] == item["tuple_b"] for x in found) != 1:
                continue
            item.update(
                point_a=a,
                point_b=b,
                status="suggested",
                evidence=evidence(
                    db,
                    "(o.point=? AND o.frame=?) OR (o.point=? AND o.frame=?)",
                    [a, item["frame_a"], b, item["frame_b"]],
                ),
            )
            suggestions.append(item)
    # Map tuple equivalence classes, including reverse direction. Small user-confirmed map only.
    parent = {}

    def root(key):
        parent.setdefault(key, key)
        while parent[key] != key:
            key = parent[key]
        return key

    seen = {}
    for m in topology.nat_mappings:
        if m.point_a not in points or m.point_b not in points:
            raise ValueError("NAT mapping references an unknown capture point")
        if points[m.point_a].device != points[m.point_b].device:
            raise ValueError("NAT mappings must join two sides of the same device")
        for a, b in ((m.tuple_a, m.tuple_b), (reverse_tuple(m.tuple_a), reverse_tuple(m.tuple_b))):
            if len(json.loads(a)) != 5 or len(json.loads(b)) != 5:
                raise ValueError("NAT tuples must have five fields")
            for p, key, other in ((m.point_a, a, b), (m.point_b, b, a)):
                conflict_key = (m.point_a, m.point_b, p, key)
                if conflict_key in seen and seen[conflict_key] != other:
                    raise ValueError("NAT mappings conflict; mapping must be one-to-one")
                seen[conflict_key] = other
            ra, rb = root(a), root(b)
            parent[rb] = ra
    for key in parent:
        db.execute("UPDATE obs SET canon=? WHERE tuple_key=?", [root(key), key])
    nets = [ipaddress.ip_network(n, strict=False) for n in topology.client_cidrs]

    def direction(key):
        _, src, _, dst, _ = json.loads(key)
        try:
            a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
            ac, bc = any(a in n for n in nets), any(b in n for n in nets)
            return "forward" if ac and not bc else "reverse" if bc and not ac else "unknown"
        except ValueError:
            return "unknown"

    db.create_function("get_direction", direction, ["VARCHAR"], "VARCHAR")
    db.create_function("reverse_key", reverse_tuple, ["VARCHAR"], "VARCHAR")
    db.execute("""UPDATE obs SET direction=get_direction(canon), packet_key=md5(canon || signature),
        flow=md5(least(canon,reverse_key(canon)))""")
    db.remove_function("get_direction")
    db.remove_function("reverse_key")
    # Compare the shared captured prefix, not the digest of different-length payloads.
    db.execute("""CREATE OR REPLACE TEMP TABLE prefix_lengths AS
        SELECT packet_key,min(coalesce(length(prefix),0)) AS n FROM obs GROUP BY packet_key""")
    db.execute("""UPDATE obs SET packet_key=md5(obs.packet_key || left(coalesce(prefix,''),p.n))
        FROM prefix_lengths p WHERE obs.packet_key=p.packet_key""")
    db.execute("""CREATE OR REPLACE TEMP TABLE key_status AS
        WITH lengths AS (SELECT packet_key,min(coalesce(length(prefix),0)) AS n FROM obs GROUP BY packet_key),
        counts AS (SELECT packet_key,max(n) AS duplicates FROM
            (SELECT packet_key,point,count(*) n FROM obs GROUP BY packet_key,point) GROUP BY packet_key)
        SELECT o.packet_key, duplicates=1 AND count(DISTINCT left(coalesce(prefix,''),l.n))=1
            AND bool_and(coalesce(unsupported,'')='') AS valid
        FROM obs o JOIN lengths l USING(packet_key) JOIN counts USING(packet_key)
        GROUP BY o.packet_key,duplicates""")
    db.execute("UPDATE obs SET eligible=s.valid FROM key_status s WHERE obs.packet_key=s.packet_key")
    return suggestions


def align(db, topology):
    points = {p.id: p for p in topology.points}
    order = list(dict.fromkeys(topology.forward + topology.reverse))
    models = {}
    ref = points[order[0]].capture_id
    epoch = db.execute("SELECT min(ts) FROM obs WHERE capture_id=?", [ref]).fetchone()[0] or 0
    models[ref] = ClockModel(0, 0, epoch, 0, "reference", "Reference capture clock", 0)
    for cid, override in topology.clock_overrides.items():
        models[cid] = ClockModel(
            override.offset_ms / 1000,
            override.drift_ppm / 1e6,
            epoch,
            None,
            "override",
            "User-supplied clock correction; uncertainty unverified",
        )
    # Multiple passes permit an asymmetric return-path point to calibrate against any known point.
    for _ in range(len(order)):
        changed = False
        for b in order:
            cid = points[b].capture_id
            if cid in models:
                continue
            for a in order:
                aid = points[a].capture_id
                if aid not in models or models[aid].offset is None:
                    continue
                data = db.execute(
                    """SELECT a.ts,b.ts,a.direction='forward',a.frame,b.frame
                    FROM obs a JOIN obs b USING(packet_key) WHERE a.point=? AND b.point=?
                    AND a.eligible AND b.eligible AND a.direction<>'unknown'
                    ORDER BY hash(a.packet_key) LIMIT 20000""",
                    [a, b],
                ).fetchall()
                # Reverse orientation if the known point is downstream in the forward path.
                flip = (
                    a in topology.forward
                    and b in topology.forward
                    and topology.forward.index(a) > topology.forward.index(b)
                )
                model = fit_clock(
                    [(models[aid].correct(x), y, not f if flip else f) for x, y, f, _, _ in data]
                )
                if model.offset is not None:
                    model.uncertainty = (model.uncertainty or 0) + (models[aid].uncertainty or 0)
                    anchors = sorted(data, key=lambda row: row[1] - models[aid].correct(row[0]))
                    chosen = anchors[:2] + anchors[-2:]
                    for _, _, _, fa, fb in chosen:
                        model.evidence.extend(
                            evidence(
                                db,
                                "(o.point=? AND o.frame=?) OR (o.point=? AND o.frame=?)",
                                [a, fa, b, fb],
                                2,
                            )
                        )
                    models[cid] = model
                    changed = True
                    break
        if not changed:
            break
    for p in order:
        models.setdefault(points[p].capture_id, ClockModel(epoch=epoch))
    for cid, model in models.items():
        if model.offset is not None:
            db.execute(
                "UPDATE obs SET corrected=?+(ts-?-?)/(1+?) WHERE capture_id=?",
                [model.epoch, model.epoch, model.offset, model.drift, cid],
            )
    return models


def analyze(project, topology: Topology | dict, progress=None):
    topology = topology if isinstance(topology, Topology) else Topology.model_validate(topology)
    if len(topology.forward) < 2:
        raise ValueError("Connect at least two capture points in a forward path")
    progress = progress or (lambda **kw: None)
    with project.connect() as db:
        project.set(db, "report", None)
        progress(state="matching")
        suggestions = prepare(db, topology)
        progress(state="aligning clocks")
        models = align(db, topology)
        db.execute(
            """UPDATE obs SET eligible=false WHERE packet_key IN (
            SELECT packet_key FROM obs GROUP BY packet_key
            HAVING max(corrected)-min(corrected)>?)""",
            [topology.match_window_ms / 1000],
        )
        points = {p.id: p for p in topology.points}
        coverage = rows(
            db,
            'SELECT point,min(corrected) AS start,max(corrected) AS "end",count(*) AS packets FROM obs GROUP BY point',
        )
        known = all(x["start"] is not None for x in coverage) and len(coverage) == len(
            set(topology.forward + topology.reverse)
        )
        common_start = max(x["start"] for x in coverage) if known else None
        common_end = min(x["end"] for x in coverage) if known else None
        if common_start is not None and common_start >= common_end:
            common_start = common_end = None
        start = topology.start if topology.start is not None else common_start
        end = topology.end if topology.end is not None else common_end
        db.execute("""CREATE OR REPLACE TABLE events (
            id VARCHAR, point_a VARCHAR,point_b VARCHAR,direction VARCHAR,kind VARCHAR,reason VARCHAR,
            packet_key VARCHAR,flow VARCHAR,ts DOUBLE,recovery_ms DOUBLE,recovery_key VARCHAR)""")
        segments, findings = [], []
        progress(state="classifying")
        for direction, path in (
            ("forward", topology.forward),
            ("reverse", topology.reverse or list(reversed(topology.forward))),
        ):
            for idx, (a, b) in enumerate(zip(path, path[1:])):
                pa, pb = points[a], points[b]
                segment_id = f"{direction}:{a}:{b}"
                unsupported = any(p.translation in ("full_proxy", "seq_randomization") for p in (pa, pb))
                pending_nat = any(
                    x["point_a"] in (a, b)
                    and x["point_b"] in (a, b)
                    and not any(
                        (m.point_a, m.point_b) == (x["point_a"], x["point_b"])
                        and (x["tuple_a"], x["tuple_b"])
                        in ((m.tuple_a, m.tuple_b), (reverse_tuple(m.tuple_a), reverse_tuple(m.tuple_b)))
                        for m in topology.nat_mappings
                    )
                    for x in suggestions
                )
                ma, mb = models[pa.capture_id], models[pb.capture_id]
                clocks_ok = ma.offset is not None and mb.offset is not None
                matched = rows(
                    db,
                    """SELECT count(*) AS matched,min(b.corrected-a.corrected)*1000 AS min_ms,
                    quantile_cont((b.corrected-a.corrected)*1000,.5) AS p50_ms,
                    quantile_cont((b.corrected-a.corrected)*1000,.95) AS p95_ms,
                    max((b.corrected-a.corrected)*1000) AS max_ms
                    FROM obs a JOIN obs b USING(packet_key) WHERE a.point=? AND b.point=?
                    AND a.direction=? AND a.eligible AND b.eligible
                    AND (? IS NULL OR a.corrected>=?) AND (? IS NULL OR a.corrected<=?)""",
                    [a, b, direction, start, start, end, end],
                )[0]
                negative = matched["min_ms"] is not None and matched["min_ms"] < -0.001
                clocks_ok = clocks_ok and not negative
                reason = (
                    "Unsupported translation boundary"
                    if unsupported
                    else "NAT mapping awaits confirmation"
                    if pending_nat
                    else "Clock alignment unreliable"
                    if not clocks_ok
                    else "No common capture coverage"
                    if common_start is None
                    else "No matched packets in selected window"
                    if not matched["matched"]
                    else None
                )
                segment = dict(
                    id=segment_id,
                    point_a=a,
                    point_b=b,
                    label=f"{pa.label} → {pb.label}",
                    location="device" if pa.device == pb.device else "link",
                    device=pa.device if pa.device == pb.device else None,
                    direction=direction,
                    reason=reason,
                    latency_confidence="estimated" if not reason else "unknown",
                    offset_uncertainty_ms=((ma.uncertainty or 0) + (mb.uncertainty or 0)) * 1000
                    if ma.uncertainty is not None and mb.uncertainty is not None
                    else None,
                    **matched,
                )
                if reason:
                    for key in ("min_ms", "p50_ms", "p95_ms", "max_ms"):
                        segment[key] = None
                downstream = path[idx + 2 :]
                db.execute(
                    """CREATE OR REPLACE TEMP TABLE missing AS SELECT a.*,
                    EXISTS(SELECT 1 FROM obs later WHERE later.packet_key=a.packet_key AND later.point IN
                        (SELECT unnest(?::VARCHAR[])) AND later.eligible) AS later_seen
                    FROM obs a WHERE a.point=? AND a.direction=? AND a.eligible
                    AND (a.length>0 OR a.proto IN ('UDP','ICMP'))
                    AND NOT EXISTS(SELECT 1 FROM obs b WHERE b.point=? AND b.packet_key=a.packet_key AND b.eligible)
                    AND (? IS NULL OR coalesce(a.corrected,a.ts)>=?) AND (? IS NULL OR coalesce(a.corrected,a.ts)<=?)""",
                    [downstream, a, direction, b, start, start, end, end],
                )
                # Re-delivery requires the same byte range and local stream; new IP ID is allowed.
                # ponytail: recoveries beyond 60 seconds stay unknown; extend for long-RTO investigations.
                db.execute(
                    """CREATE OR REPLACE TEMP TABLE recoveries AS
                    SELECT m.packet_key,min(r.corrected) AS recovery_time,arg_min(r.packet_key,r.corrected) AS recovery_key,
                    count(*) AS attempts
                    FROM missing m JOIN obs r ON r.point=? AND r.canon=m.canon AND r.proto='TCP'
                    AND r.seq=m.seq AND r.length=m.length AND r.corrected>m.corrected
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
                    AND u.seq=m.seq AND u.length=m.length AND u.corrected>m.corrected
                    AND u.corrected<=r.recovery_time GROUP BY m.packet_key""")
                db.execute("""UPDATE recoveries SET attempts=c.attempts FROM retry_counts c
                    WHERE recoveries.packet_key=c.packet_key""")
                db.create_function("rev_canon", reverse_tuple, ["VARCHAR"], "VARCHAR")
                db.execute(
                    """CREATE OR REPLACE TEMP TABLE acked AS
                    SELECT DISTINCT m.packet_key FROM missing m JOIN obs ack ON ack.point=? AND ack.proto='TCP'
                    AND ack.stream=m.stream AND ack.canon=rev_canon(m.canon) AND (ack.flags & 16)>0
                    AND ack.corrected>m.corrected AND ack.corrected<=m.corrected+60
                    AND ((ack.ack-m.seq-m.length+4294967296)%4294967296)<2147483648
                    WHERE m.proto='TCP' AND m.length>0 AND NOT EXISTS(
                        SELECT 1 FROM obs r WHERE r.point=m.point AND r.canon=m.canon AND r.seq=m.seq
                        AND r.stream=m.stream AND r.length=m.length AND r.corrected>m.corrected AND r.corrected<ack.corrected)""",
                    [a],
                )
                db.remove_function("rev_canon")
                db.execute(
                    """INSERT INTO events
                    SELECT md5(? || m.packet_key),?,?,?,
                    CASE WHEN later_seen THEN 'capture_miss'
                        WHEN ? IS NOT NULL OR ? IS NULL OR m.corrected<? OR m.corrected>? THEN 'unknown'
                        WHEN ack.packet_key IS NOT NULL THEN 'capture_miss'
                        WHEN r.recovery_time IS NOT NULL THEN CASE WHEN (r.recovery_time-m.corrected)*1000>=? OR r.attempts>1
                            THEN 'impactful_loss' ELSE 'recovered_loss' END ELSE 'unknown' END,
                    CASE WHEN later_seen THEN 'Packet appears again farther along the path'
                        WHEN ? IS NOT NULL THEN ? WHEN ? IS NULL OR m.corrected<? OR m.corrected>? THEN 'Outside common coverage; absence is not proof of loss'
                        WHEN ack.packet_key IS NOT NULL THEN 'Receiver acknowledged these bytes without a preceding retransmission'
                        WHEN r.recovery_time IS NOT NULL THEN 'Original missing downstream; repeated byte range was delivered'
                        ELSE 'Disappearance without delivery or positive device-drop evidence; cause unknown' END,
                    m.packet_key,m.flow,coalesce(m.corrected,m.ts),(r.recovery_time-m.corrected)*1000,r.recovery_key
                    FROM missing m LEFT JOIN recoveries r USING(packet_key) LEFT JOIN acked ack USING(packet_key)""",
                    [
                        segment_id,
                        a,
                        b,
                        direction,
                        reason,
                        common_start,
                        common_start,
                        common_end,
                        topology.stall_ms,
                        reason,
                        reason,
                        common_start,
                        common_start,
                        common_end,
                    ],
                )
                total = db.execute(
                    """SELECT count(*) FROM obs WHERE point=? AND direction=? AND eligible
                    AND (length>0 OR proto IN ('UDP','ICMP'))
                    AND (? IS NULL OR coalesce(corrected,ts)>=?) AND (? IS NULL OR coalesce(corrected,ts)<=?)""",
                    [a, direction, start, start, end, end],
                ).fetchone()[0]
                classes = rows(
                    db,
                    """SELECT kind,count(*) AS count,min(ts) AS first_seen,max(ts) AS last_seen,
                    max(recovery_ms) AS max_recovery_ms FROM events WHERE point_a=? AND point_b=? AND direction=? GROUP BY kind""",
                    [a, b, direction],
                )
                segment.update(eligible_packets=total, classes={x["kind"]: x["count"] for x in classes})
                loss_count = sum(
                    x["count"] for x in classes if x["kind"] in ("recovered_loss", "impactful_loss")
                )
                segment["loss_percent"] = 100 * loss_count / total if total and not reason else None
                for cls in classes:
                    severity = {
                        "impactful_loss": "high",
                        "recovered_loss": "low",
                        "capture_miss": "quality",
                        "unknown": "unknown",
                    }[cls["kind"]]
                    event = db.execute(
                        """SELECT packet_key,recovery_key FROM events WHERE point_a=? AND point_b=? AND direction=? AND kind=? ORDER BY ts LIMIT 1""",
                        [a, b, direction, cls["kind"]],
                    ).fetchone()
                    refs = evidence(db, "o.packet_key IN (?,?)", list(event))
                    findings.append(
                        dict(
                            id=f"{segment_id}:{cls['kind']}",
                            type=cls["kind"],
                            severity=severity,
                            hop=segment_id,
                            direction=direction,
                            time_range=[cls["first_seen"], cls["last_seen"]],
                            confidence="supported" if severity != "unknown" else "unknown",
                            metrics=cls,
                            summary=f"{cls['count']} {cls['kind'].replace('_', ' ')} event(s) between {pa.label} and {pb.label}.",
                            evidence=refs,
                            evidence_note="First event shown; select the hop to browse all events",
                        )
                    )
                segments.append(segment)
        progress(state="summarizing")
        db.execute("""CREATE OR REPLACE TABLE flow_summary AS
            WITH base AS (SELECT flow,min(corrected) AS start,max(corrected) AS "end",count(DISTINCT point) AS points,
                count(DISTINCT packet_key) AS unique_observations,count(*) FILTER(WHERE retrans) AS retrans_observations,
                bool_or((flags&4)>0) AS has_reset, max(rtt)*1000 AS max_rtt_ms,
                min(canon) AS tuple, count(*) FILTER(WHERE (flags&2)>0 AND (flags&16)=0) AS syns,
                count(*) FILTER(WHERE (flags&18)=18) AS synacks FROM obs GROUP BY flow),
            bytes AS (SELECT flow,sum(length) AS bytes FROM
                (SELECT flow,packet_key,max(length) AS length FROM obs GROUP BY flow,packet_key) GROUP BY flow),
            losses AS (SELECT flow,count(*) FILTER(WHERE kind='impactful_loss') AS impactful_loss,
                count(*) FILTER(WHERE kind='recovered_loss') AS recovered_loss,
                count(*) FILTER(WHERE kind='capture_miss') AS capture_miss,max(recovery_ms) AS max_stall_ms
                FROM events GROUP BY flow)
            SELECT base.*,bytes.bytes,coalesce(impactful_loss,0) AS impactful_loss,
                coalesce(recovered_loss,0) AS recovered_loss,coalesce(capture_miss,0) AS capture_miss,max_stall_ms,
                syns>0 AND synacks=0 AS handshake_incomplete
            FROM base JOIN bytes USING(flow) LEFT JOIN losses USING(flow)""")
        quality = rows(
            db,
            """SELECT point,count(*) AS packets,count(*) FILTER(WHERE NOT eligible) AS excluded,
            count(*) FILTER(WHERE caplen<wirelen) AS truncated,count(*) FILTER(WHERE length>1500) AS possible_offload,
            count(*) FILTER(WHERE direction='unknown') AS unknown_direction FROM obs GROUP BY point""",
        )
        inventories = {
            cid: json.loads(inv) for cid, inv in db.execute("SELECT id,inventory FROM captures").fetchall()
        }
        for q in quality:
            inv = inventories[points[q["point"]].capture_id]
            q["ifdrop"], q["osdrop"] = inv.get("ifdrop"), inv.get("osdrop")
            q["evidence"] = evidence(
                db,
                "o.point=? AND (NOT o.eligible OR o.caplen<o.wirelen OR o.length>1500 OR o.direction='unknown')",
                [q["point"]],
                5,
            )
        rank = {"high": 0, "low": 1, "quality": 2, "unknown": 3}
        findings.sort(key=lambda f: (rank[f["severity"]], f["time_range"][0]))
        total_findings = len(findings)
        order_scores = rows(
            db,
            """SELECT point,median(ttl) AS median_ttl,median(corrected) AS median_time,count(*) AS samples
            FROM obs o WHERE direction='forward' AND eligible AND EXISTS(
                SELECT 1 FROM obs b WHERE b.packet_key=o.packet_key AND b.point<>o.point AND b.eligible)
            GROUP BY point ORDER BY median_ttl DESC,median_time,point""",
        )
        auto_order = dict(
            points=[p["point"] for p in order_scores],
            scores=order_scores,
            reason="Suggestion from median TTL and corrected timestamps of shared packets. Your saved drawing remains authoritative.",
        )
        inconclusive_quality = any(
            q["unknown_direction"] == q["packets"] or q["excluded"] == q["packets"] for q in quality
        )
        report = dict(
            schema_version=1,
            generated_at=datetime.now(timezone.utc).isoformat(),
            verdict="Impactful loss observed"
            if any(f["severity"] == "high" for f in findings)
            else "Recovered loss observed"
            if any(f["severity"] == "low" for f in findings)
            else "Inconclusive"
            if inconclusive_quality
            or any(s["reason"] for s in segments)
            or any(f["severity"] == "unknown" for f in findings)
            else "No supported network loss in the selected window",
            scope="Phase 1; first event times are not change-point onset estimates",
            window=dict(start=start, end=end, common_start=common_start, common_end=common_end),
            clocks={cid: model.json() for cid, model in models.items()},
            coverage=coverage,
            quality=quality,
            auto_order_suggestion=auto_order,
            nat_suggestions=suggestions,
            segments=segments,
            findings=findings[:200],
            finding_count=total_findings,
            flow_count=db.execute("SELECT count(*) FROM flow_summary").fetchone()[0],
            limitations=[
                "Observed coverage does not prove uninterrupted capture.",
                "Latency is estimated under minimum-path symmetry; offsets include possible path asymmetry.",
                "Repeated/ambiguous fingerprints, fragments and unsupported transports are excluded.",
                "Conversation rows aggregate a canonical 5-tuple; reused TCP sessions may share a row.",
                "Unrecovered disappearance cannot confirm a device drop without positive device evidence.",
            ],
        )
        project.set(db, "topology", topology.model_dump())
        project.set(db, "report", report)
        return report


def flow_page(project, offset=0, limit=50, search="", filter_by="", sort="bytes"):
    with project.connect() as db:
        if not project.get(db, "report"):
            return {"total": 0, "items": []}
        clauses, params = ["tuple ILIKE ?"], ["%" + search + "%"]
        filters = {
            "impactful": "impactful_loss>0",
            "resets": "has_reset",
            "handshakes": "handshake_incomplete",
        }
        if filter_by in filters:
            clauses.append(filters[filter_by])
        order = (
            sort
            if sort in ("bytes", "max_stall_ms", "impactful_loss", "retrans_observations", "start")
            else "bytes"
        )
        where = " AND ".join(clauses)
        total = db.execute("SELECT count(*) FROM flow_summary WHERE " + where, params).fetchone()[0]
        return dict(
            total=total,
            items=rows(
                db,
                f"SELECT * FROM flow_summary WHERE {where} ORDER BY {order} DESC NULLS LAST,flow LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ),
        )


def ladder(project, flow, offset=0, limit=150):
    with project.connect() as db:
        if not project.get(db, "report"):
            return {"items": [], "total": 0, "events": []}
        keys = rows(
            db,
            """SELECT packet_key,min(corrected) AS ts,bool_or(retrans) AS retrans,
            min(seq) AS seq,min(ack) AS ack,min(flags) AS flags,min(length) AS length,min(direction) AS direction
            FROM obs WHERE flow=? GROUP BY packet_key ORDER BY ts NULLS LAST,packet_key LIMIT ? OFFSET ?""",
            [flow, limit, offset],
        )
        for key in keys:
            key["evidence"] = evidence(db, "o.packet_key=?", [key["packet_key"]], 64)
        events = rows(db, "SELECT * FROM events WHERE flow=? ORDER BY ts LIMIT 200", [flow])
        local_metrics = rows(
            db,
            """SELECT point,min(tuple_key) AS tuple,min(reverse_tuple) AS reverse_tuple,
            count(*) FILTER(WHERE retrans) AS retransmissions,count(*) FILTER(WHERE zero_window) AS zero_windows,
            count(*) FILTER(WHERE (flags&4)>0) AS resets,max(rtt)*1000 AS max_rtt_ms
            FROM obs WHERE flow=? GROUP BY point ORDER BY point""",
            [flow],
        )
        for metric in local_metrics:
            handshake = rows(
                db,
                """SELECT s.frame AS syn_frame,sa.frame AS synack_frame,
                (sa.ts-s.ts)*1000 AS syn_to_synack_ms,min(a.ts-sa.ts)*1000 AS synack_to_ack_ms
                FROM obs s JOIN obs sa ON sa.point=s.point AND sa.stream=s.stream
                AND (sa.flags&18)=18 AND sa.ack=(s.seq+1)%4294967296 AND sa.ts>s.ts AND sa.ts<s.ts+60
                LEFT JOIN obs a ON a.point=s.point AND a.stream=s.stream AND a.tuple_key=s.tuple_key
                AND (a.flags&18)=16 AND a.ack=(sa.seq+1)%4294967296 AND a.ts>sa.ts AND a.ts<sa.ts+60
                WHERE s.point=? AND s.flow=? AND s.proto='TCP' AND (s.flags&18)=2
                GROUP BY s.frame,sa.frame,s.ts,sa.ts ORDER BY s.ts LIMIT 1""",
                [metric["point"], flow],
            )
            metric["handshake"] = handshake[0] if handshake else None

        total = db.execute("SELECT count(DISTINCT packet_key) FROM obs WHERE flow=?", [flow]).fetchone()[0]
        return dict(items=keys, total=total, events=events, local_metrics=local_metrics)


def event_page(project, a, b, direction, offset=0, limit=50):
    with project.connect() as db:
        data = rows(
            db,
            """SELECT * FROM events WHERE point_a=? AND point_b=? AND direction=? ORDER BY ts LIMIT ? OFFSET ?""",
            [a, b, direction, limit, offset],
        )
        for item in data:
            item["evidence"] = evidence(
                db, "o.packet_key IN (?,?)", [item["packet_key"], item["recovery_key"]]
            )
        return dict(
            items=data,
            total=db.execute(
                "SELECT count(*) FROM events WHERE point_a=? AND point_b=? AND direction=?", [a, b, direction]
            ).fetchone()[0],
        )
