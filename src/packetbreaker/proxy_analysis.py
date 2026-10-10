"""Application request graph across independent full-proxy TCP legs."""

import json

from .evidence import evidence
from .proxy_matching import pair_requests
from .store import rows


def boundaries(topology):
    points = {p.id: p for p in topology.points}
    found = []
    for a, b in zip(topology.forward, topology.forward[1:]):
        pa, pb = points[a], points[b]
        if (
            pa.device == pb.device
            and "full_proxy" in (pa.translation, pb.translation)
            and pa.vendor != "f5"
            and pb.vendor != "f5"
        ):
            found.append((pa, pb))
    return found


def uncertainty(models, a, b):
    ma, mb = models.get(a.capture_id), models.get(b.capture_id)
    if (
        not ma
        or not mb
        or ma.uncertainty is None
        or mb.uncertainty is None
        or ma.confidence == "unknown"
        or mb.confidence == "unknown"
    ):
        return None
    return 0.0 if a.capture_id == b.capture_id else ma.uncertainty + mb.uncertainty


def refs(db, *requests):
    keys = set()
    for r in requests:
        if r:
            keys.update(
                (r["point"], r[f]) for f in ("first_frame", "last_frame", "response_frame") if r.get(f)
            )
    if not keys:
        return []
    return evidence(
        db,
        " OR ".join("(o.point=? AND o.frame=?)" for _ in keys),
        [v for k in sorted(keys) for v in k],
        limit=len(keys),
        _expand_ranges=False,
    )


def prepare_requests(db):
    # Components come from tshark reassembly, not captured-prefix parsing.
    db.execute("""CREATE OR REPLACE TABLE proxy_requests AS
    WITH app AS (SELECT *,md5(point||':'||frame::VARCHAR||':'||kind) AS id FROM app_protocol WHERE kind IN ('http_request','tls_setup')),
    components AS (SELECT a.id,arg_max(o.frame,(e.seq-o.seq+4294967296)%4294967296) AS first_frame,
        min(o.corrected) AS earliest, bool_and(o.eligible) AS usable
        FROM app a JOIN obs e ON e.point=a.point AND e.frame=a.frame
        JOIN obs o ON o.point=a.point AND o.frame IN (SELECT unnest(from_json(a.components,'["BIGINT"]')))
        GROUP BY a.id),
    responses AS (SELECT a.id,arg_min(r.frame,ro.corrected) AS completion_frame
        FROM app a JOIN app_protocol r ON r.point=a.point AND r.protocol_stream=a.protocol_stream
        AND ((a.kind='http_request' AND r.kind='http_response' AND try_cast(json_extract_string(r.metadata,'$.request_in') AS BIGINT)=a.frame)
        OR (a.kind='tls_setup' AND r.kind='tls_server' AND r.frame>a.frame
            AND NOT EXISTS(SELECT 1 FROM app n WHERE n.point=a.point AND n.protocol_stream=a.protocol_stream AND n.kind='tls_setup' AND n.frame>a.frame AND n.frame<r.frame)))
        JOIN obs ro ON ro.point=r.point AND ro.frame=r.frame GROUP BY a.id),
    response_start AS (SELECT r.id,arg_max(o.frame,(e.seq-o.seq+4294967296)%4294967296) AS response_frame
        FROM responses r JOIN app a ON a.id=r.id JOIN app_protocol p ON p.point=a.point AND p.frame=r.completion_frame AND p.kind IN ('http_response','tls_server')
        JOIN obs e ON e.point=p.point AND e.frame=p.frame JOIN obs o ON o.point=p.point AND o.frame IN (SELECT unnest(from_json(p.components,'["BIGINT"]'))) GROUP BY r.id)
    SELECT a.id,a.point,a.frame AS last_frame,c.first_frame,r.response_frame,e.flow,e.canon,s.seq AS start_seq,
        CASE WHEN a.kind='http_request' THEN 'http' ELSE 'tls_setup' END AS kind,
        coalesce(json_extract_string(a.metadata,'$.xff[0]'),s.src) AS origin_ip,
        json_extract_string(a.metadata,'$.line') AS line,json_extract_string(a.metadata,'$.host') AS host,
        coalesce(from_json(json_extract(a.metadata,'$.xff'),'["VARCHAR"]'),[]::VARCHAR[]) AS xff,
        json_extract_string(a.metadata,'$.sni') AS sni,
        coalesce(try_cast(json_extract_string(a.metadata,'$.ready') AS BOOLEAN),false) AND c.usable AS ready,
        CASE WHEN NOT c.usable THEN 'Unmatchable request components' ELSE json_extract_string(a.metadata,'$.reason') END AS reason,
        s.corrected AS start,e.corrected AS complete,ro.corrected AS response,
        a.protocol_stream
    FROM app a JOIN obs e ON e.point=a.point AND e.frame=a.frame
    JOIN components c ON c.id=a.id JOIN obs s ON s.point=a.point AND s.frame=c.first_frame
    LEFT JOIN response_start r ON r.id=a.id LEFT JOIN obs ro ON ro.point=a.point AND ro.frame=r.response_frame""")
    # HTTP/1.x responses preserve request order. tshark's request_in is not reliable for
    # pipelining. Require both handshakes and continuous decoded request/response byte ranges.
    db.execute("""CREATE OR REPLACE TEMP TABLE http_pdus AS
        WITH data AS (SELECT a.*,e.canon,e.seq+e.length AS end_seq,e.corrected AS completion,
            arg_max(o.frame,(e.seq-o.seq+4294967296)%4294967296) AS first_frame,
            bool_and(o.eligible AND coalesce(try_cast(json_extract_string(a.metadata,'$.ready') AS BOOLEAN),false)) AS ready
            FROM app_protocol a JOIN obs e ON e.point=a.point AND e.frame=a.frame
            JOIN obs o ON o.point=a.point AND o.frame IN (SELECT unnest(from_json(a.components,'["BIGINT"]')))
            WHERE a.kind='http_request' OR (a.kind='http_response' AND try_cast(json_extract_string(a.metadata,'$.code') AS INTEGER)>=200)
            GROUP BY ALL), ordered AS (SELECT d.*,s.seq AS start_seq,s.corrected AS first_time,
            row_number() OVER w AS ordinal,lag(end_seq) OVER w AS previous_end
            FROM data d JOIN obs s ON s.point=d.point AND s.frame=d.first_frame
            WINDOW w AS (PARTITION BY d.point,d.protocol_stream,d.kind ORDER BY d.frame))
        SELECT *,ready AND CASE WHEN ordinal=1 THEN EXISTS(SELECT 1 FROM obs h WHERE h.point=ordered.point
            AND h.canon=ordered.canon AND (h.flags&2)=2 AND (h.seq+1)%4294967296=start_seq)
            ELSE previous_end%4294967296=start_seq END AS contiguous FROM ordered""")
    db.execute("UPDATE proxy_requests SET response=NULL,response_frame=NULL WHERE kind='http'")
    db.execute("""UPDATE proxy_requests SET response=p.first_time,response_frame=p.first_frame
        FROM http_pdus q JOIN http_pdus p ON q.point=p.point AND q.protocol_stream=p.protocol_stream AND q.ordinal=p.ordinal
        WHERE proxy_requests.point=q.point AND proxy_requests.last_frame=q.frame AND proxy_requests.kind='http'
        AND q.kind='http_request' AND p.kind='http_response' AND p.first_time>=q.completion
        AND NOT EXISTS(SELECT 1 FROM http_pdus x WHERE x.point=q.point AND x.protocol_stream=q.protocol_stream AND NOT x.contiguous)
        AND (SELECT count(*) FROM http_pdus x WHERE x.point=q.point AND x.protocol_stream=q.protocol_stream AND x.kind='http_response')
            <=(SELECT count(*) FROM http_pdus x WHERE x.point=q.point AND x.protocol_stream=q.protocol_stream AND x.kind='http_request')""")


def correlate(db, topology, models, statuses):
    prepare_requests(db)
    requests = rows(db, "SELECT * FROM proxy_requests ORDER BY start,point,last_frame")
    lookup = {r["id"]: r for r in requests}
    failures = {s["point"]: s["reason"] for s in statuses if s["reason"]}
    found = []
    for a, b in boundaries(topology):
        clients = [r for r in requests if r["point"] == a.id]
        servers = [r for r in requests if r["point"] == b.id]
        pairs = pair_requests(
            clients, servers, topology.match_window_ms / 1000, uncertainty(models, a, b), db=db
        )
        if not pairs:
            pairs = [
                dict(
                    status="unknown",
                    client_id=None,
                    server_id=None,
                    reason=failures.get(a.id)
                    or failures.get(b.id)
                    or "No decoded application requests at this proxy",
                )
            ]
        for pair in pairs:
            c, s = lookup.get(pair["client_id"]), lookup.get(pair["server_id"])
            pair.update(
                device=a.device,
                point_a=a.id,
                point_b=b.id,
                kind=(c or s or {}).get("kind"),
                client_flow=c["flow"] if c else None,
                server_flow=s["flow"] if s else None,
                time=(c or s or {}).get("start"),
                evidence=refs(db, c, s),
            )
            if failures.get(a.id) or failures.get(b.id):
                pair.update(status="unknown", reason=failures.get(a.id) or failures.get(b.id))
            found.append(pair)
    db.execute(
        "CREATE OR REPLACE TABLE proxy_pairs(device VARCHAR,client_id VARCHAR,server_id VARCHAR,status VARCHAR,metadata VARCHAR)"
    )
    if found:
        db.executemany(
            "INSERT INTO proxy_pairs VALUES (?,?,?,?,?)",
            [(p["device"], p["client_id"], p["server_id"], p["status"], json.dumps(p)) for p in found],
        )
    return dict(
        transactions=found[:200],
        transaction_count=len(found),
        request_count=len(requests),
        note="Requests pair across independent TCP legs. SNI pairs visible TLS setup only; encrypted application request boundaries remain unknown.",
    )
