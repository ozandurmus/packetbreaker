import ipaddress
import json

from ..byte_ranges import add_byte_calibration
from ..evidence import evidence
from ..matching import partition_proxy_legs, prepare_occurrences
from ..store import rows
from ..translation import normalize_sequences
from .selection import restrict_index_scope, reverse_tuple, select_observations


def _find_nat_suggestions(db, topology, points):
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
            ORDER BY samples DESC,tuple_a,tuple_b LIMIT 1000""",
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
    return nat_points, suggestions


def _canonicalize_tuples(db, topology, points):
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
    if any(p.vendor == "f5" for p in topology.points):
        db.execute("""UPDATE obs SET direction=CASE
            WHEN (c.role='client') = (lower(json_extract_string(obs.vendor,'$."f5ethtrailer.ingress"')) IN ('true','1')) THEN 'forward'
            ELSE 'reverse' END FROM f5_connections c WHERE obs.capture_id=c.capture_id AND obs.stream=c.stream
            AND c.role IN ('client','server') AND json_extract_string(obs.vendor,'$."f5ethtrailer.ingress"') IS NOT NULL""")


def prepare(db, topology, project=None, cancel=None):
    select_observations(db, topology, project, cancel)
    points = {p.id: p for p in topology.points}
    nat_points, suggestions = _find_nat_suggestions(db, topology, points)
    _canonicalize_tuples(db, topology, points)
    restrict_index_scope(db, topology)
    normalize_sequences(db, topology)
    partition_proxy_legs(db, topology)
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
    from ..udp_index import index_udp

    if project is not None:
        index_udp(project, db, topology, cancel)
    db.execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
        CASE WHEN o.proto='UDP' AND d."sip.Call-ID" IS NOT NULL AND d."sip.CSeq.seq" IS NOT NULL
          AND NOT contains(d."sip.CSeq.seq",',') AND o.caplen=o.wirelen
          THEN md5(o.canon||'sip:'||d."sip.Call-ID"||':'||d."sip.CSeq.seq"||':'||coalesce(d."sip.CSeq.method",'')||':'||coalesce(d."sip.Status-Code",'request'))
          ELSE o.packet_key END AS packet_key) FROM obs o LEFT JOIN udp_decoded d USING(point,frame)""")
    prepare_occurrences(db, topology.duplicate_us)
    if db.execute("SELECT count(*) FROM obs WHERE proto='TCP' AND length>1500 AND eligible").fetchone()[0]:
        add_byte_calibration(db)
    return suggestions
