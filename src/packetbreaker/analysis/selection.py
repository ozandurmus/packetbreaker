import ipaddress
import json

from ..ingest import tuple_id
from ..fragments import normalize_fragments
from ..vendors import point_selector, prepare_f5_connections


def reverse_tuple(key):
    proto, src, sport, dst, dport = json.loads(key)
    return tuple_id(proto, dst, dport, src, sport)


def _append_host_scope_clause(db, topology, point, used):
    if not (point.host_capture and any(not p.host_capture and p.id in used for p in topology.points)):
        return ""
    # Non-host points have already selected/decapsulated their identities. Keep both local NAT tuples.
    db.execute(
        "CREATE OR REPLACE TEMP TABLE path_tuples AS SELECT DISTINCT least(tuple_key,reverse_tuple) AS tuple_key FROM obs"
    )
    mapped = [
        key
        for mapping in topology.nat_mappings
        for key in (
            mapping.tuple_a,
            mapping.tuple_b,
            reverse_tuple(mapping.tuple_a),
            reverse_tuple(mapping.tuple_b),
        )
    ]
    if mapped:
        db.executemany("INSERT INTO path_tuples VALUES (?)", [(k,) for k in mapped])
    nets = [ipaddress.ip_network(n, strict=False) for n in topology.client_cidrs]
    addresses = db.execute(
        "SELECT DISTINCT src FROM packets WHERE capture_id=? UNION SELECT DISTINCT dst FROM packets WHERE capture_id=?",
        [point.capture_id, point.capture_id],
    ).fetchall()
    chosen = [(a,) for (a,) in addresses if a and any(ipaddress.ip_address(a) in n for n in nets)]
    db.execute("CREATE OR REPLACE TEMP TABLE selected_clients(ip VARCHAR)")
    if chosen:
        db.executemany("INSERT INTO selected_clients VALUES (?)", chosen)
    return " AND (least(tuple_key,reverse_tuple) IN (SELECT tuple_key FROM path_tuples) OR tuple_key IN (SELECT tuple_key FROM path_tuples) OR src IN(SELECT ip FROM selected_clients) OR dst IN(SELECT ip FROM selected_clients))"


def _apply_point_post_filters(project, db, point, cancel):
    if project is not None:
        from ..capture_layers import apply_layers

        apply_layers(project, db, point, cancel)
    if point.source_cidr:
        network = ipaddress.ip_network(point.source_cidr, strict=False)
        addresses = db.execute("SELECT DISTINCT src FROM obs WHERE point=?", [point.id]).fetchall()
        accepted = [(src,) for (src,) in addresses if src and ipaddress.ip_address(src) in network]
        db.execute("CREATE OR REPLACE TEMP TABLE point_sources(src VARCHAR)")
        if accepted:
            db.executemany("INSERT INTO point_sources VALUES (?)", accepted)
        db.execute(
            "DELETE FROM obs WHERE point=? AND (src IS NULL OR src NOT IN (SELECT src FROM point_sources))",
            [point.id],
        )
    if point.vendor == "paloalto":
        db.execute(
            "UPDATE obs SET vendor=? WHERE point=?",
            [
                json.dumps(
                    dict(
                        adapter="paloalto",
                        stage=point.vendor_stage,
                        device=point.device,
                        stage_source="user_file_tag",
                    )
                ),
                point.id,
            ],
        )


def select_observations(db, topology, project=None, cancel=None):
    db.execute("DROP VIEW IF EXISTS observation_matches")
    db.execute("CREATE OR REPLACE TABLE byte_flows(flow VARCHAR,direction VARCHAR)")
    db.execute("DROP TABLE IF EXISTS obs")
    db.execute(
        "CREATE TABLE obs AS SELECT *, seq AS raw_seq, ack AS raw_ack, NULL::VARCHAR AS translation_reason, NULL::VARCHAR AS range_reason, NULL::VARCHAR AS point, NULL::VARCHAR AS canon FROM packets WHERE false"
    )
    prepare_f5_connections(db, topology)
    ready = {r[0] for r in db.execute("SELECT id FROM captures WHERE state='ready'").fetchall()}
    used = set(topology.forward + (topology.reverse or list(reversed(topology.forward))))
    used.update(p.id for p in topology.points if p.vendor == "paloalto")
    db.execute(
        "CREATE OR REPLACE TABLE analysis_scope(point VARCHAR,input_frames BIGINT,retained_frames BIGINT,excluded_single_point_frames BIGINT,excluded_single_point_flows BIGINT)"
    )
    for point in sorted(topology.points, key=lambda p: p.host_capture):
        if point.id not in used:
            continue
        if point.capture_id not in ready:
            raise ValueError(f"{point.label}: capture is not ready")
        clause, params = "capture_id=?", [point.capture_id]
        extra, values = point_selector(point)
        clause += extra
        params += values
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
        input_frames = db.execute(f"SELECT count(*) FROM packets WHERE {clause}", params).fetchone()[0]
        input_flows = db.execute(
            f"SELECT count(DISTINCT least(tuple_key,reverse_tuple)) FROM packets WHERE {clause}", params
        ).fetchone()[0]
        clause += _append_host_scope_clause(db, topology, point, used)
        retained = db.execute(f"SELECT count(*) FROM packets WHERE {clause}", params).fetchone()[0]
        retained_flows = db.execute(
            f"SELECT count(DISTINCT least(tuple_key,reverse_tuple)) FROM packets WHERE {clause}",
            params,
        ).fetchone()[0]
        db.execute(
            "INSERT INTO analysis_scope VALUES (?,?,?,?,?)",
            [point.id, input_frames, retained, input_frames - retained, input_flows - retained_flows],
        )
        db.execute(
            f"INSERT INTO obs SELECT *,seq,ack,NULL,NULL,?,tuple_key FROM packets WHERE {clause}",
            [point.id, *params],
        )
        _apply_point_post_filters(project, db, point, cancel)
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
    normalize_fragments(db)


def restrict_index_scope(db, topology):
    # Canonical flow IDs include confirmed NAT mappings. Explicit proxy/stage evidence must survive.
    evidence_points = [
        p.id
        for p in topology.points
        if p.translation == "full_proxy" or p.vendor in ("f5", "paloalto", "checkpoint")
    ]
    nets = [ipaddress.ip_network(n, strict=False) for n in topology.client_cidrs]
    selected = []
    for (canon,) in db.execute("SELECT DISTINCT canon FROM obs").fetchall():
        try:
            key = json.loads(canon)
            if any(ipaddress.ip_address(ip) in net for ip in (key[1], key[3]) for net in nets):
                selected.append((canon,))
        except (ValueError, TypeError, IndexError):
            pass
    db.execute("CREATE OR REPLACE TEMP TABLE client_tuples(canon VARCHAR)")
    if selected:
        db.executemany("INSERT INTO client_tuples VALUES (?)", selected)
    db.execute("""CREATE OR REPLACE TEMP TABLE scoped_flows AS SELECT flow FROM obs GROUP BY flow
        HAVING count(DISTINCT point)>=2 OR bool_or(canon IN(SELECT canon FROM client_tuples))""")
    db.execute(
        """CREATE OR REPLACE TABLE index_scope AS SELECT point,count(*) AS input_frames,count(DISTINCT flow) AS input_flows,
        count(*) FILTER(WHERE flow IN(SELECT flow FROM scoped_flows) OR point IN(SELECT unnest(?::VARCHAR[]))) AS retained_frames,
        count(DISTINCT flow) FILTER(WHERE flow IN(SELECT flow FROM scoped_flows) OR point IN(SELECT unnest(?::VARCHAR[]))) AS retained_flows
        FROM obs GROUP BY point""",
        [evidence_points, evidence_points],
    )
    db.execute(
        """UPDATE index_scope SET input_frames=s.input_frames,input_flows=index_scope.input_flows+s.excluded_single_point_flows FROM analysis_scope s WHERE index_scope.point=s.point"""
    )
    db.execute(
        "CREATE OR REPLACE TABLE obs AS SELECT * FROM obs WHERE flow IN(SELECT flow FROM scoped_flows) OR point IN(SELECT unnest(?::VARCHAR[]))",
        [evidence_points],
    )
    db.execute("""UPDATE analysis_scope SET retained_frames=i.retained_frames,
        excluded_single_point_frames=analysis_scope.input_frames-i.retained_frames FROM index_scope i WHERE analysis_scope.point=i.point""")
