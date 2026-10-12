"""Validate tshark reassembly membership and normalize one observation per IP datagram."""

from .store import rows
from .evidence import evidence

FRAGMENT_STATUS = """CASE WHEN invalid>0 OR starts<>1 OR tails>1 THEN 'unknown'
    WHEN tails=0 OR gaps>0 OR decoded=0 THEN 'incomplete' ELSE 'complete' END"""


def normalize_fragments(db):
    # Physical wire observations remain separate for sub-bucket rate measurements.
    db.execute("""CREATE OR REPLACE TABLE wire_observations AS SELECT point,capture_id,frame,ts,
        wirelen,caplen,frame_hash,length AS transport_length FROM obs""")
    db.execute("""CREATE OR REPLACE TABLE fragment_members AS SELECT point,frame,src,dst,proto,
        raw_seq,ipid,ts,caplen,wirelen,
        json_extract_string(path_fields,'$.fragment.id') AS fragment_id,
        json_extract_string(path_fields,'$.fragment.protocol') AS fragment_protocol,
        json_extract_string(path_fields,'$.fragment.family') AS family,
        try_cast(json_extract_string(path_fields,'$.fragment.offset') AS BIGINT) AS off,
        try_cast(json_extract_string(path_fields,'$.fragment.size') AS BIGINT) AS size,
        try_cast(json_extract_string(path_fields,'$.fragment.more') AS BOOLEAN) AS more,
        try_cast(json_extract_string(path_fields,'$.fragment.complete') AS BOOLEAN) AS decoded,
        try_cast(json_extract_string(path_fields,'$.fragment.invalid') AS BOOLEAN) AS invalid,
        json_extract_string(path_fields,'$.fragment.target') AS target,
        json_extract_string(path_fields,'$.tunnel.vni') AS vni
        FROM obs WHERE json_exists(path_fields,'$.fragment')""")
    db.execute("""CREATE OR REPLACE TEMP TABLE fragment_episodes AS
        SELECT *,sum(CASE WHEN off=0 THEN 1 ELSE 0 END) OVER(
            PARTITION BY point,src,dst,fragment_id,fragment_protocol,vni ORDER BY ts,frame) AS episode
        FROM fragment_members""")
    db.execute("""CREATE OR REPLACE TEMP TABLE fragment_spans AS SELECT *,
        coalesce('t:'||target,'e:'||episode::VARCHAR) AS assembly,
        lag(off+size) OVER(PARTITION BY point,src,dst,fragment_id,fragment_protocol,vni,
            coalesce('t:'||target,'e:'||episode::VARCHAR) ORDER BY off,frame) AS prior_end
        FROM fragment_episodes""")
    db.execute(
        """CREATE OR REPLACE TABLE fragment_groups AS WITH g AS (
        SELECT point,src,dst,fragment_id,fragment_protocol,vni,assembly,min(family) AS family,
        count(*) AS fragments,list(frame ORDER BY frame) AS members,
        min(ts) AS first_ts,max(ts) AS last_ts,min(frame) AS first_frame,
        coalesce(min(frame) FILTER(WHERE decoded),min(frame)) AS frame,
        count(*) FILTER(WHERE invalid OR caplen<wirelen OR size<=0 OR prior_end>off) AS invalid,
        count(*) FILTER(WHERE off=0) AS starts,count(*) FILTER(WHERE NOT more) AS tails,
        count(*) FILTER(WHERE prior_end<off) AS gaps,count(*) FILTER(WHERE decoded) AS decoded,
        arg_min(raw_seq,frame) AS first_seq,min(ipid) AS ipid
        FROM fragment_spans GROUP BY point,src,dst,fragment_id,fragment_protocol,vni,assembly)
        SELECT *,"""
        + FRAGMENT_STATUS
        + """ AS status FROM g"""
    )
    # Multiple incomplete uses of the same identity cannot safely assign stray continuations.
    db.execute("""UPDATE fragment_groups SET status='unknown' WHERE status<>'complete' AND
        (point,src,dst,fragment_id,fragment_protocol) IN (
        SELECT point,src,dst,fragment_id,fragment_protocol FROM fragment_groups WHERE status<>'complete'
        GROUP BY ALL HAVING count(*)>1)""")
    db.execute("""UPDATE obs SET unsupported=CASE WHEN g.status='complete' THEN ''
            WHEN g.status='incomplete' THEN 'Incomplete IP datagram: one or more fragments missing'
            ELSE 'Overlapping, truncated or inconsistent fragments; datagram identity unknown' END,
        path_fields=json_merge_patch(obs.path_fields,json_object('fragment',json_object(
            'status',g.status,'members',g.members,'count',g.fragments,'id',g.fragment_id,
            'family',g.family,'protocol',g.fragment_protocol,'first_time',g.first_ts,'last_time',g.last_ts)))
        FROM fragment_groups g WHERE obs.point=g.point AND obs.frame=g.frame""")
    db.execute("""DELETE FROM obs WHERE (point,frame) IN (
        SELECT g.point,unnest(g.members) FROM fragment_groups g
        EXCEPT SELECT point,frame FROM fragment_groups)""")


def guard_missing(db, point):
    db.execute(
        """UPDATE missing SET range_unknown='Overlapping or inconsistent fragments at the next point; disappearance unknown'
        WHERE EXISTS(SELECT 1 FROM fragment_groups g JOIN obs b ON b.point=g.point AND b.frame=g.frame
            WHERE g.point=? AND g.status='unknown' AND missing.canon=b.canon
            AND missing.raw_seq=g.first_seq AND missing.ipid=g.ipid)""",
        [point],
    )


def fragment_findings(db, topology, segments):
    pointmap = {p.id: p for p in topology.points}
    findings = []
    for seg in segments:
        if seg.get("loss_percent") is None:
            continue
        direction, a, b = seg["id"].split(":")
        data = rows(
            db,
            """SELECT a.frame AS before,b.frame AS after,b.flow,b.corrected,g.fragments,g.members,g.fragment_id,g.status
            FROM obs a JOIN obs b ON a.flow=b.flow AND (a.packet_key=b.packet_key OR (json_extract_string(b.path_fields,'$.fragment.status')='incomplete' AND a.canon=b.canon AND a.ipid=b.ipid AND a.seq=b.seq AND a.ack=b.ack AND a.flags=b.flags AND a.length>0 AND b.corrected>=a.corrected AND b.corrected-a.corrected<=?))
            JOIN fragment_groups g ON g.point=b.point AND g.frame=b.frame
            WHERE a.point=? AND b.point=? AND a.direction=? AND a.eligible AND (b.eligible OR g.status='incomplete')
            AND g.status IN ('complete','incomplete') AND NOT json_exists(a.path_fields,'$.fragment')
            QUALIFY count(*) OVER(PARTITION BY b.point,b.frame)=1 ORDER BY b.corrected LIMIT 100""",
            [topology.match_window_ms / 1000, a, b, direction],
        )
        pa, pb = pointmap[a], pointmap[b]
        device = pa.device if pa.device == pb.device else None
        location = device or f"link between {pa.label} and {pb.label}"
        for r in data:
            refs = evidence(
                db,
                "(o.point=? AND o.frame=?) OR (o.point=? AND o.frame=?)",
                [a, r["before"], b, r["after"]],
                128,
            )
            findings.append(
                dict(
                    id=f"fragment:{seg['id']}:{r['after']}",
                    type="fragmentation",
                    hop=seg["id"],
                    device=device,
                    direction=direction,
                    flow=r["flow"],
                    time_range=[r["corrected"], r["corrected"]],
                    metrics=dict(
                        datagrams=1,
                        fragments=r["fragments"],
                        fragment_id=r["fragment_id"],
                        reassembly=r["status"],
                    ),
                    evidence=refs,
                    confidence="supported",
                    severity="quality",
                    cause="observed_transformation",
                    summary=f"Fragmented by {location} (first observed here)",
                    tooltip="One uniquely identified datagram is unfragmented upstream and has fragment headers downstream; incomplete reassembly is reported separately. The first observed boundary is supported; an unseen internal device is not identified.",
                )
            )
    quality = rows(
        db,
        """SELECT point,status,count(*) AS datagrams,sum(fragments) AS physical_fragments
        FROM fragment_groups GROUP BY ALL ORDER BY point,status""",
    )
    return findings, quality
