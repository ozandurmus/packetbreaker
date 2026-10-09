import ipaddress
import json
from datetime import datetime, timezone

from . import __version__
from .clock import ClockModel, fit_clock
from .matching import prepare_occurrences, match_occurrences, link_tcp_sessions, propagate_translation_unknown
from .ingest import tuple_id
from .headlines import add_headlines
from .evidence import evidence, prepare_flow_filters
from .store import rows
from .topology import Topology
from .timeseries import build_timeseries
from .onset import add_onsets
from .translation import normalize_sequences, sequence_report
from .byte_ranges import (
    add_byte_calibration,
    prepare_byte_ranges,
    range_condition,
    range_later_seen,
    range_recoveries,
    range_ack_guard,
    range_notes,
)


def reverse_tuple(key):
    proto, src, sport, dst, dport = json.loads(key)
    return tuple_id(proto, dst, dport, src, sport)


def prepare(db, topology):
    db.execute("DROP VIEW IF EXISTS observation_matches")
    db.execute("CREATE OR REPLACE TABLE byte_flows(flow VARCHAR,direction VARCHAR)")
    db.execute("DROP TABLE IF EXISTS obs")
    db.execute(
        "CREATE TABLE obs AS SELECT *, seq AS raw_seq, ack AS raw_ack, NULL::VARCHAR AS translation_reason, NULL::VARCHAR AS range_reason, NULL::VARCHAR AS point, NULL::VARCHAR AS canon FROM packets WHERE false"
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
            addresses = db.execute("SELECT DISTINCT src FROM packets WHERE " + clause, params).fetchall()
            accepted = [(src,) for (src,) in addresses if src and ipaddress.ip_address(src) in network]
            db.execute("CREATE OR REPLACE TEMP TABLE point_sources(src VARCHAR)")
            if accepted:
                db.executemany("INSERT INTO point_sources VALUES (?)", accepted)
            clause += " AND src IN (SELECT src FROM point_sources)"
        db.execute(
            f"INSERT INTO obs SELECT *,seq,ack,NULL,NULL,?,tuple_key FROM packets WHERE {clause}",
            [point.id, *params],
        )
    db.execute("ALTER TABLE obs ADD COLUMN corrected DOUBLE")
    db.execute("ALTER TABLE obs ADD COLUMN direction VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN canon_reverse VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN packet_key VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN flow VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN eligible BOOLEAN DEFAULT false")
    # A single frame selected by two points cannot prove transit between them.
    duplicates = db.execute("""SELECT count(*) FROM (SELECT capture_id,frame FROM obs
        GROUP BY capture_id,frame HAVING count(*)>1)""").fetchone()[0]
    if duplicates:
        raise ValueError("Capture-point selections overlap: use distinct file/interface/source filters")
    points = {p.id: p for p in topology.points}
    nat_points = sorted(
        {
            point
            for a, b in zip(topology.forward, topology.forward[1:])
            if points[a].device == points[b].device
            and "nat" in (points[a].translation, points[b].translation)
            for point in (a, b)
        }
    )
    db.execute(
        """CREATE OR REPLACE TEMP TABLE nat_candidates AS
        SELECT *,md5(signature || left(prefix,16)) AS nat_key FROM obs
        WHERE coalesce(unsupported,'')='' AND length(prefix)>=16 AND point IN (SELECT unnest(?::VARCHAR[]))
        QUALIFY count(*) OVER(PARTITION BY point,nat_key)=1""",
        [nat_points],
    )
    suggestions = []
    for a, b in zip(topology.forward, topology.forward[1:]):
        pa, pb = points[a], points[b]
        if pa.device != pb.device or "nat" not in (pa.translation, pb.translation):
            continue
        found = rows(
            db,
            """SELECT a.tuple_key AS tuple_a,b.tuple_key AS tuple_b,count(*) AS samples,
            min(b.ts-a.ts) AS min_delta,max(b.ts-a.ts) AS max_delta,min(a.frame) AS frame_a,arg_min(b.frame,a.frame) AS frame_b
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
    nets = [ipaddress.ip_network(n, strict=False) for n in topology.client_cidrs]

    def direction(key):
        _, src, _, dst, _ = json.loads(key)
        try:
            a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
            ac, bc = any(a in n for n in nets), any(b in n for n in nets)
            return "forward" if ac and not bc else "reverse" if bc and not ac else "unknown"
        except ValueError:
            return "unknown"

    db.execute(
        "CREATE OR REPLACE TEMP TABLE tuple_lookup(tuple_key VARCHAR,canon VARCHAR,canon_reverse VARCHAR,direction VARCHAR)"
    )
    distinct = db.execute("SELECT DISTINCT tuple_key FROM obs").fetchall()
    metadata = []
    for (key,) in distinct:
        canon = root(key) if key in parent else key
        metadata.append((key, canon, reverse_tuple(canon), direction(canon)))
    if metadata:
        db.executemany("INSERT INTO tuple_lookup VALUES (?,?,?,?)", metadata)
    db.execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
        t.canon AS canon,t.canon_reverse AS canon_reverse,t.direction AS direction,
        md5(t.canon || o.signature) AS packet_key,md5(least(t.canon,t.canon_reverse)) AS flow)
        FROM obs o JOIN tuple_lookup t ON o.tuple_key=t.tuple_key""")
    normalize_sequences(db, topology)
    # Compare the shared captured prefix, not the digest of different-length payloads.
    db.execute("""CREATE OR REPLACE TEMP TABLE prefix_lengths AS
        SELECT packet_key,min(coalesce(length(prefix),0)) AS n FROM obs GROUP BY packet_key""")
    db.execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
        md5(o.packet_key || left(coalesce(o.prefix,''),p.n)) AS packet_key)
        FROM obs o JOIN prefix_lengths p ON o.packet_key=p.packet_key""")
    db.execute(
        """CREATE OR REPLACE TEMP TABLE nat_point_tuples AS
        SELECT DISTINCT point,canon FROM obs WHERE point IN (SELECT unnest(?::VARCHAR[]))""",
        [nat_points],
    )
    prepare_occurrences(db, topology.duplicate_us)
    if db.execute("SELECT count(*) FROM obs WHERE proto='TCP' AND length>1500 AND eligible").fetchone()[0]:
        add_byte_calibration(db)
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
                    FROM calibration a JOIN calibration b USING(packet_key) WHERE a.point=? AND b.point=?
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
    db.execute(
        "CREATE OR REPLACE TEMP TABLE clock_values(capture_id VARCHAR,epoch DOUBLE,offset_s DOUBLE,drift DOUBLE)"
    )
    db.executemany(
        "INSERT INTO clock_values VALUES (?,?,?,?)",
        [(cid, m.epoch, m.offset, m.drift) for cid, m in models.items()],
    )
    db.execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
        c.epoch+(o.ts-c.epoch-c.offset_s)/(1+c.drift) AS corrected)
        FROM obs o LEFT JOIN clock_values c USING(capture_id)""")
    return models


def analyze(project, topology: Topology | dict, progress=None):
    topology = topology if isinstance(topology, Topology) else Topology.model_validate(topology)
    if len(topology.forward) < 2:
        raise ValueError("Connect at least two capture points in a forward path")
    progress = progress or (lambda **kw: None)
    with project.connect() as db:
        db.execute("SET preserve_insertion_order=false")
        project.set(db, "report", None)
        progress(state="matching")
        suggestions = prepare(db, topology)
        progress(state="aligning clocks")
        models = align(db, topology)
        match_occurrences(db, topology)
        link_tcp_sessions(db, topology)
        propagate_translation_unknown(db)
        byte_active = prepare_byte_ranges(db, topology)
        prepare_flow_filters(db)
        for suggestion in suggestions:
            suggestion["evidence"] = evidence(
                db,
                "(o.point=? AND o.frame=?) OR (o.point=? AND o.frame=?)",
                [suggestion["point_a"], suggestion["frame_a"], suggestion["point_b"], suggestion["frame_b"]],
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
            packet_key VARCHAR,flow VARCHAR,ts DOUBLE,recovery_ms DOUBLE,recovery_key VARCHAR,
            support_key VARCHAR,impact_ms DOUBLE,is_data BOOLEAN,missing_bytes BIGINT,byte_ranges VARCHAR)""")
        inventories = {
            cid: json.loads(inv) for cid, inv in db.execute("SELECT id,inventory FROM captures").fetchall()
        }
        segments, findings = [], []
        progress(state="classifying")
        for direction, path in (
            ("forward", topology.forward),
            ("reverse", topology.reverse or list(reversed(topology.forward))),
        ):
            for idx, (a, b) in enumerate(zip(path, path[1:])):
                pa, pb = points[a], points[b]
                segment_id = f"{direction}:{a}:{b}"
                unsupported = any(p.translation == "full_proxy" for p in (pa, pb))
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
                if pa.device == pb.device and "nat" in (pa.translation, pb.translation):
                    confirmed = []
                    for m in topology.nat_mappings:
                        if {m.point_a, m.point_b} == {a, b}:
                            confirmed.extend(
                                (m.tuple_a, m.tuple_b, reverse_tuple(m.tuple_a), reverse_tuple(m.tuple_b))
                            )
                    unresolved = db.execute(
                        """SELECT count(*) FROM nat_point_tuples x WHERE x.point IN (?,?)
                        AND NOT EXISTS(SELECT 1 FROM nat_point_tuples y WHERE y.point IN (?,?) AND y.point<>x.point AND y.canon=x.canon)
                        AND x.canon NOT IN (SELECT canon FROM tuple_lookup WHERE tuple_key IN (SELECT unnest(?::VARCHAR[])))""",
                        [a, b, a, b, confirmed],
                    ).fetchone()[0]
                    pending_nat = pending_nat or unresolved > 0
                ma, mb = models[pa.capture_id], models[pb.capture_id]
                clocks_ok = ma.offset is not None and mb.offset is not None
                matched = rows(
                    db,
                    """SELECT count(*) AS matched,min(time_b-time_a)*1000 AS min_ms,
                    quantile_cont((time_b-time_a)*1000,.5) AS p50_ms,
                    quantile_cont((time_b-time_a)*1000,.95) AS p95_ms,
                    max((time_b-time_a)*1000) AS max_ms
                    FROM observation_matches WHERE point_a=? AND point_b=? AND direction=?
                    AND (? IS NULL OR time_a>=?) AND (? IS NULL OR time_a<=?)""",
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
                    else "Selected window is outside common coverage"
                    if start is None or end is None or end < common_start or start > common_end
                    else None
                )
                classification_reason = reason
                quality_rows = rows(
                    db,
                    """SELECT point,
                    CASE WHEN direction='unknown' THEN 'direction_unknown'
                         WHEN NOT eligible THEN coalesce(excluded_reason,'unsupported_identity') ELSE 'eligible' END AS reason,
                    count(*) AS count FROM obs WHERE point IN (?,?) AND (direction=? OR direction='unknown')
                    AND (? IS NULL OR coalesce(corrected,ts)>=?) AND (? IS NULL OR coalesce(corrected,ts)<=?)
                    GROUP BY point,reason""",
                    [a, b, direction, start, start, end, end],
                )
                endpoint_quality = {}
                excluded_counts = {}
                for endpoint in (a, b):
                    q = [r for r in quality_rows if r["point"] == endpoint]
                    n = sum(r["count"] for r in q)
                    good = sum(r["count"] for r in q if r["reason"] == "eligible")
                    excluded = {r["reason"]: r["count"] for r in q if r["reason"] != "eligible"}
                    endpoint_quality[endpoint] = dict(
                        total=n, eligible=good, excluded=excluded, eligible_ratio=good / n if n else None
                    )
                    inv = inventories[points[endpoint].capture_id]
                    time_bad = inv.get("timestamp_excluded_counts", {})
                    if time_bad:
                        total_valid = inv.get("packet_count", 0)
                        temporal_ratio = total_valid / (total_valid + sum(time_bad.values()))
                        current = endpoint_quality[endpoint]["eligible_ratio"]
                        endpoint_quality[endpoint]["eligible_ratio"] = (
                            min(current, temporal_ratio) if current is not None else temporal_ratio
                        )
                        endpoint_quality[endpoint]["timestamp_quality_scope"] = (
                            "whole capture; invalid times cannot be placed in the selected window"
                        )
                        excluded.update(time_bad)
                    for key, value in excluded.items():
                        excluded_counts[key] = excluded_counts.get(key, 0) + value
                ratios = [
                    q["eligible_ratio"] for q in endpoint_quality.values() if q["eligible_ratio"] is not None
                ]
                eligible_ratio = min(ratios) if ratios else 0.0
                if eligible_ratio < topology.min_eligible_ratio:
                    detail = (
                        ", ".join(f"{k}: {v}" for k, v in sorted(excluded_counts.items()))
                        or "no observations"
                    )
                    reason = f"Insufficient matchable packets ({100 * (1 - eligible_ratio):.1f}% excluded: {detail})"
                segment = dict(
                    eligible_ratio=eligible_ratio,
                    excluded_counts=excluded_counts,
                    endpoint_quality=endpoint_quality,
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
                        WHEN ack.packet_key IS NOT NULL THEN 'Receiver ACK, DNS response, or echo reply proves delivery without an earlier retry'
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
                    in ("recovered_loss", "impactful_loss", "unrecovered_loss", "handshake_blocked")
                )
                segment["loss_percent"] = 100 * loss_count / total if total and not reason else None
                for cls in classes:
                    severity = {
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
                            severity=severity,
                            hop=segment_id,
                            direction=direction,
                            time_range=[cls["first_seen"], cls["last_seen"]],
                            confidence="supported" if severity != "unknown" else "unknown",
                            metrics=cls,
                            cause="unknown" if cls["kind"] != "capture_miss" else "capture_visibility",
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
                segments.append(segment)
        progress(state="summarizing")
        db.execute("""CREATE OR REPLACE TABLE flow_summary AS
            WITH base AS (SELECT flow,max(coalesce(translation_reason,range_reason)) AS matching_unknown_reason,min(corrected) AS start,max(corrected) AS "end",count(DISTINCT point) AS points,
                count(DISTINCT packet_key) AS unique_observations,count(*) FILTER(WHERE retrans) AS retrans_observations,
                bool_or((flags&4)>0) AS has_reset, max(rtt)*1000 AS max_rtt_ms,
                min(canon) AS tuple, count(*) FILTER(WHERE (flags&2)>0 AND (flags&16)=0) AS syns,
                count(*) FILTER(WHERE (flags&18)=18) AS synacks FROM obs GROUP BY flow),
            bytes AS (SELECT flow,sum(length) AS bytes FROM
                (SELECT flow,packet_key,max(length) AS length FROM obs GROUP BY flow,packet_key) GROUP BY flow),
            losses AS (SELECT flow,count(*) FILTER(WHERE kind='impactful_loss') AS impactful_loss,
                count(*) FILTER(WHERE kind='recovered_loss') AS recovered_loss,
                count(*) FILTER(WHERE kind='capture_miss') AS capture_miss,
                count(*) FILTER(WHERE kind='unrecovered_loss') AS unrecovered_loss,
                count(*) FILTER(WHERE kind='handshake_blocked') AS handshake_blocked,
                count(*) FILTER(WHERE kind='unknown') AS unknown_events,
                max(greatest(impact_ms,recovery_ms)) AS max_stall_ms
                FROM events GROUP BY flow)
            SELECT base.*,bytes.bytes,coalesce(impactful_loss,0) AS impactful_loss,
                coalesce(recovered_loss,0) AS recovered_loss,coalesce(capture_miss,0) AS capture_miss,max_stall_ms,
                coalesce(unrecovered_loss,0) AS unrecovered_loss,coalesce(handshake_blocked,0) AS handshake_blocked,
                coalesce(unknown_events,0) AS unknown_events,
                (syns>0 AND synacks=0) OR coalesce(handshake_blocked,0)>0 AS handshake_incomplete
            FROM base JOIN bytes USING(flow) LEFT JOIN losses USING(flow)""")
        if byte_active:
            db.execute("""UPDATE flow_summary SET bytes=x.bytes FROM (
                SELECT flow,sum(length) AS bytes FROM (
                    SELECT o.flow,o.packet_key,max(o.length) AS length FROM obs o WHERE NOT
                        (o.proto='TCP' AND o.length>0 AND EXISTS(SELECT 1 FROM byte_flows f WHERE f.flow=o.flow AND f.direction=o.direction))
                        GROUP BY o.flow,o.packet_key
                    UNION ALL SELECT flow,packet_key,max(range_length) FROM byte_obs WHERE is_atom AND eligible GROUP BY flow,packet_key)
                GROUP BY flow) x WHERE flow_summary.flow=x.flow""")
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
        add_headlines(db, findings, segments, topology, end)
        progress(state="building time series")
        time_window = dict(start=start, end=end, common_start=common_start, common_end=common_end)
        timeseries = build_timeseries(db, topology, segments, coverage, time_window)
        onsets = add_onsets(db, topology, segments)
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
            schema_version=2,
            sequence_translations=sequence_report(db),
            offload_points=range_notes(db) if byte_active else [],
            timeseries=timeseries,
            onsets=onsets,
            engine_version=__version__,
            generated_at=datetime.now(timezone.utc).isoformat(),
            verdict="Impactful loss observed"
            if any(f["type"] == "impactful_loss" for f in findings)
            else "Handshake failure observed"
            if any(f["type"] == "handshake_blocked" for f in findings)
            else "Loss observed"
            if any(f["severity"] == "low" for f in findings)
            else "Inconclusive"
            if inconclusive_quality
            or any(s["reason"] for s in segments)
            or any(f["severity"] == "unknown" for f in findings)
            else "No supported network loss in the selected window",
            scope="Phase 2 / Part 2; supported bucket-level onset estimates with clock uncertainty",
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
                "SPAN duplicates, unresolved occurrence timing collisions, fragments and unsupported transports are excluded.",
                "TCP sessions are joined by shared occurrences; streams without a shared packet stay separate.",
                "Unrecovered disappearance cannot confirm a device drop without positive device evidence.",
            ],
        )
        project.set(db, "topology", topology.model_dump())
        project.set(db, "report", report)
        return report


def flow_page(project, offset=0, limit=50, search="", filter_by="", sort="bytes", start=None, end=None):
    with project.connect() as db:
        if not project.get(db, "report"):
            return {"total": 0, "items": []}
        clauses, params = ["tuple ILIKE ?"], ["%" + search + "%"]
        if start is not None or end is not None:
            clauses.append(
                "EXISTS(SELECT 1 FROM obs o WHERE o.flow=flow_summary.flow AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?))"
            )
            params.extend([start, start, end, end])
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


def ladder(project, flow, offset=0, limit=150, start=None, end=None):
    with project.connect() as db:
        if not project.get(db, "report"):
            return {"items": [], "total": 0, "events": []}
        keys = rows(
            db,
            """SELECT packet_key,min(corrected) AS ts,bool_or(retrans) AS retrans,
            min(seq) AS seq,min(ack) AS ack,min(flags) AS flags,min(length) AS length,min(direction) AS direction
            FROM obs WHERE flow=? AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?) GROUP BY packet_key ORDER BY ts NULLS LAST,packet_key LIMIT ? OFFSET ?""",
            [flow, start, start, end, end, limit, offset],
        )
        for key in keys:
            key["evidence"] = evidence(db, "o.packet_key=?", [key["packet_key"]], 64)
        events = rows(
            db,
            "SELECT * FROM events WHERE flow=? AND (? IS NULL OR ts>=?) AND (? IS NULL OR ts<?) ORDER BY ts LIMIT 200",
            [flow, start, start, end, end],
        )
        local_metrics = rows(
            db,
            """SELECT point,min(tuple_key) AS tuple,min(reverse_tuple) AS reverse_tuple,
            count(*) FILTER(WHERE retrans) AS retransmissions,count(*) FILTER(WHERE zero_window) AS zero_windows,
            count(*) FILTER(WHERE (flags&4)>0) AS resets,max(rtt)*1000 AS max_rtt_ms
            FROM obs WHERE flow=? AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?) GROUP BY point ORDER BY point""",
            [flow, start, start, end, end],
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
                AND (? IS NULL OR s.corrected>=?) AND (? IS NULL OR s.corrected<?)
                GROUP BY s.frame,sa.frame,s.ts,sa.ts ORDER BY s.ts LIMIT 1""",
                [metric["point"], flow, start, start, end, end],
            )
            metric["handshake"] = handshake[0] if handshake else None

        total = db.execute(
            "SELECT count(DISTINCT packet_key) FROM obs WHERE flow=? AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?)",
            [flow, start, start, end, end],
        ).fetchone()[0]
        filters = rows(
            db,
            """SELECT f.capture_id,c.name AS file,f.display_filter FROM flow_filters f
            JOIN captures c ON c.id=f.capture_id WHERE f.flow=? ORDER BY c.name""",
            [flow],
        )
        return dict(items=keys, total=total, events=events, local_metrics=local_metrics, flow_filters=filters)


def event_page(project, a, b, direction, offset=0, limit=50, start=None, end=None):
    with project.connect() as db:
        data = rows(
            db,
            """SELECT * FROM events WHERE point_a=? AND point_b=? AND direction=? AND (? IS NULL OR ts>=?) AND (? IS NULL OR ts<?) ORDER BY ts LIMIT ? OFFSET ?""",
            [a, b, direction, start, start, end, end, limit, offset],
        )
        for item in data:
            if item.get("byte_ranges"):
                item["byte_ranges"] = json.loads(item["byte_ranges"])
            item["evidence"] = evidence(
                db, "o.packet_key IN (?,?,?)", [item["packet_key"], item["recovery_key"], item["support_key"]]
            )
        return dict(
            items=data,
            total=db.execute(
                "SELECT count(*) FROM events WHERE point_a=? AND point_b=? AND direction=? AND (? IS NULL OR ts>=?) AND (? IS NULL OR ts<?)",
                [a, b, direction, start, start, end, end],
            ).fetchone()[0],
        )


def findings_page(project, start=None, end=None):
    with project.connect() as db:
        report = project.get(db, "report")
        if not report:
            return dict(items=[])
        if start is None and end is None:
            return dict(items=report["findings"])
        groups = rows(
            db,
            """SELECT point_a,point_b,direction,kind,count(*) AS count,min(ts) AS first,max(ts) AS last,
            max(recovery_ms) AS max_recovery_ms FROM events WHERE (? IS NULL OR ts>=?) AND (? IS NULL OR ts<?)
            GROUP BY point_a,point_b,direction,kind ORDER BY first""",
            [start, start, end, end],
        )
        originals = {f["id"]: f for f in report["findings"]}
        items = []
        for g in groups:
            hop = f"{g['direction']}:{g['point_a']}:{g['point_b']}"
            key = hop + ":" + g["kind"]
            f = originals.get(key)
            if not f:
                continue
            event = db.execute(
                """SELECT packet_key,recovery_key,support_key FROM events WHERE point_a=? AND point_b=?
                AND direction=? AND kind=? AND (? IS NULL OR ts>=?) AND (? IS NULL OR ts<?) ORDER BY ts LIMIT 1""",
                [g["point_a"], g["point_b"], g["direction"], g["kind"], start, start, end, end],
            ).fetchone()
            text = f"{g['count']} {g['kind'].replace('_', ' ')} events in the selected interval."
            items.append(
                {
                    **f,
                    "headline": text,
                    "summary": text,
                    "time_range": [g["first"], g["last"]],
                    "metrics": {"count": g["count"], "max_recovery_ms": g["max_recovery_ms"]},
                    "evidence": evidence(db, "o.packet_key IN (?,?,?)", list(event)),
                }
            )
        return dict(items=items)
