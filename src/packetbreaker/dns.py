"""Scoped DNS transactions and observed timeout/disappearance evidence."""

from ipaddress import ip_address
from .evidence import evidence
from .store import rows
from .topology import Topology

OUTCOME = """CASE WHEN NOT complete OR ambiguous THEN 'unknown'
    WHEN unique_response THEN 'answered' WHEN NOT covered THEN 'unknown'
    WHEN query_hop IS NOT NULL THEN 'query_disappeared'
    WHEN far_responses=1 AND response_hop IS NOT NULL THEN 'response_disappeared'
    WHEN far_responses>0 THEN 'unknown'
    WHEN resolver_seen AND resolver_covered THEN 'resolver_timeout' ELSE 'unknown' END"""
TOOLTIP = "Same-point query-to-response latency, scoped by TCP/UDP conversation, reversed tuple, DNS ID, question name/type/class and a bounded deadline. A timeout is an observation, not proof of resolver internals."
REASONS = {
    "answered": "Unique question/tuple/transaction response at this point before the configured deadline",
    "query_disappeared": "Query disappearance is independently classified on the monitored path; resolver failure is not established",
    "response_disappeared": "Resolver response is visible before its supported disappearance on the return path; this is not a resolver timeout",
    "resolver_timeout": "Query reached the declared resolver-side capture, with coverage through its deadline and no response observed there; internal cause unknown",
}


def prepare(project, db, topology, report):
    generation = [report["generated_at"], topology.dns_timeout_ms, 1]
    if project.get(db, "dns_generation") == generation:
        return
    db.execute("""CREATE OR REPLACE TABLE dns_observations AS SELECT o.*,
        lower(json_extract_string(path_fields,'$.dns_name')) AS question,
        try_cast(json_extract_string(path_fields,'$.dns_type') AS INTEGER) AS qtype,
        try_cast(json_extract_string(path_fields,'$.dns_class') AS INTEGER) AS qclass,
        try_cast(json_extract_string(path_fields,'$.dns_questions') AS INTEGER) AS questions,
        try_cast(json_extract_string(path_fields,'$.dns_rcode') AS INTEGER) AS rcode,
        coalesce(try_cast(json_extract_string(path_fields,'$.dns_index') AS INTEGER)=1,false) AS indexed
        FROM obs o WHERE dns_id IS NOT NULL AND proto IN('TCP','UDP')""")
    destinations = [
        r[0]
        for r in db.execute("SELECT DISTINCT dst FROM dns_observations WHERE NOT dns_response").fetchall()
    ]
    db.execute("CREATE OR REPLACE TEMP TABLE dns_unicast(resolver VARCHAR,unicast BOOLEAN)")
    if destinations:
        db.executemany(
            "INSERT INTO dns_unicast VALUES (?,?)",
            [(a, not ip_address(a).is_multicast) for a in destinations],
        )
    db.execute("""CREATE OR REPLACE TABLE dns_queries AS SELECT q.*,q.dst AS resolver,
        coalesce(q.indexed AND q.eligible AND q.question IS NOT NULL AND q.qtype IS NOT NULL AND q.qclass IS NOT NULL
            AND q.questions=1 AND u.unicast,false) AS complete
        FROM dns_observations q LEFT JOIN dns_unicast u ON u.resolver=q.dst WHERE NOT q.dns_response""")
    db.execute(
        """CREATE OR REPLACE TEMP TABLE dns_candidates AS WITH c AS(
        SELECT q.point,q.frame,r.frame AS response_frame,r.ts AS response_ts,r.corrected AS response_time,r.packet_key AS response_key,r.rcode
        FROM dns_queries q JOIN dns_observations r ON q.point=r.point AND q.flow=r.flow
        AND q.tuple_key=r.reverse_tuple AND q.dns_id=r.dns_id AND q.question=r.question AND q.qtype=r.qtype AND q.qclass=r.qclass
        WHERE q.complete AND r.eligible AND r.indexed AND r.dns_response AND r.questions=1 AND r.ts>=q.ts AND r.ts<=q.ts+?)
        SELECT *,count(*) OVER(PARTITION BY point,response_frame) AS request_candidates FROM c""",
        [topology.dns_timeout_ms / 1000],
    )
    db.execute(
        """CREATE OR REPLACE TABLE dns_local_pairs AS
        SELECT q.*,coalesce(c.candidates,0) AS candidates,coalesce(c.ambiguous,false) AS ambiguous,
        coalesce(c.candidates=1 AND NOT c.ambiguous,false) AS unique_response,
        CASE WHEN c.candidates=1 AND NOT c.ambiguous THEN c.response_frame END AS response_frame,
        CASE WHEN c.candidates=1 AND NOT c.ambiguous THEN c.response_ts END AS response_ts,
        CASE WHEN c.candidates=1 AND NOT c.ambiguous THEN c.response_time END AS response_time,
        CASE WHEN c.candidates=1 AND NOT c.ambiguous THEN c.response_key END AS response_key,
        CASE WHEN c.candidates=1 AND NOT c.ambiguous THEN c.rcode END AS rcode_answer,
        q.ts+?<=coverage.stop AS covered
        FROM dns_queries q LEFT JOIN(SELECT point,frame,count(*) AS candidates,bool_or(request_candidates<>1) AS ambiguous,
            min(response_frame) AS response_frame,min(response_ts) AS response_ts,min(response_time) AS response_time,min(response_key) AS response_key,min(rcode) AS rcode
            FROM dns_candidates GROUP BY ALL) c USING(point,frame)
        LEFT JOIN(SELECT point,max(ts) AS stop FROM obs GROUP BY point) coverage USING(point)""",
        [topology.dns_timeout_ms / 1000],
    )
    db.execute("CREATE OR REPLACE TEMP TABLE dns_supported_hops(hop VARCHAR)")
    hops = [(s["id"],) for s in report["segments"] if s.get("loss_percent") is not None]
    if hops:
        db.executemany("INSERT INTO dns_supported_hops VALUES (?)", hops)
    db.execute("""CREATE OR REPLACE TEMP TABLE dns_losses AS SELECT packet_key,
        arg_min(direction||':'||point_a||':'||point_b,ts) AS hop
        FROM events WHERE kind IN('unrecovered_loss','recovered_loss','impactful_loss','confirmed_device_drop')
        AND direction||':'||point_a||':'||point_b IN(SELECT hop FROM dns_supported_hops) GROUP BY packet_key""")
    db.execute("CREATE OR REPLACE TEMP TABLE dns_resolver_points(point VARCHAR)")
    server_points = [(p.id,) for p in topology.points if p.kind == "Server"]
    if server_points:
        db.executemany("INSERT INTO dns_resolver_points VALUES (?)", server_points)
    db.execute("""CREATE OR REPLACE TEMP TABLE dns_far AS
        SELECT q.point,q.frame,count(DISTINCT p.response_key) FILTER(WHERE p.unique_response) AS far_responses,
        min(p.response_key) FILTER(WHERE p.unique_response) AS far_response_key,
        bool_or(p.point IN(SELECT point FROM dns_resolver_points)) AS resolver_seen,
        bool_or(p.point IN(SELECT point FROM dns_resolver_points) AND p.covered AND p.corrected IS NOT NULL AND q.corrected IS NOT NULL) AS resolver_covered,
        min(p.point) FILTER(WHERE p.point IN(SELECT point FROM dns_resolver_points)) AS resolver_point,
        min(p.frame) FILTER(WHERE p.point IN(SELECT point FROM dns_resolver_points)) AS resolver_frame
        FROM dns_local_pairs q LEFT JOIN dns_local_pairs p ON q.flow=p.flow AND q.packet_key=p.packet_key
        AND q.question=p.question AND q.qtype=p.qtype AND q.qclass=p.qclass GROUP BY q.point,q.frame""")
    db.execute("""CREATE OR REPLACE TABLE dns_signals AS
        SELECT q.*,coalesce(f.far_responses,0) AS far_responses,coalesce(f.resolver_seen,false) AS resolver_seen,
        coalesce(f.resolver_covered,false) AS resolver_covered,f.resolver_point,f.resolver_frame,f.far_response_key,
        ql.hop AS query_hop,rl.hop AS response_hop FROM dns_local_pairs q
        LEFT JOIN dns_far f USING(point,frame) LEFT JOIN dns_losses ql ON ql.packet_key=q.packet_key
        LEFT JOIN dns_losses rl ON rl.packet_key=f.far_response_key""")
    db.execute(
        "CREATE OR REPLACE TABLE dns_transactions AS SELECT *,"
        + OUTCOME
        + """ AS status,
        CASE WHEN unique_response THEN (response_ts-ts)*1000 END AS latency_ms,
        CASE WHEN complete AND candidates=0 AND covered THEN true WHEN unique_response THEN false END AS timeout_observed
        FROM dns_signals"""
    )
    project.set(db, "dns_generation", generation)


def dns_page(project, point=None, resolver=None, start=None, end=None, offset=0, limit=100):
    with project.connect() as db:
        report = project.get(db, "report")
        raw = project.get(db, "topology")
        if not report or not raw:
            return dict(
                items=[], total=0, summary=[], points=[], reason="Run analysis first", tooltip=TOOLTIP
            )
        topology = Topology.model_validate(raw)
        prepare(project, db, topology, report)
        where = "(? IS NULL OR point=?) AND (? IS NULL OR resolver=?) AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?)"
        params = [point, point, resolver, resolver, start, start, end, end]
        summary = rows(
            db,
            """SELECT point,resolver,count(*) AS queries,count(*) FILTER(WHERE complete) AS matchable_queries,
            count(latency_ms) AS answered,count(*) FILTER(WHERE timeout_observed) AS timed_out_queries,
            count(*) FILTER(WHERE status='unknown') AS unknown_queries,
            quantile_cont(latency_ms,.5) AS p50_ms,quantile_cont(latency_ms,.95) AS p95_ms,max(latency_ms) AS max_ms
            FROM dns_transactions WHERE """
            + where
            + " GROUP BY ALL ORDER BY point,resolver",
            params,
        )
        data = rows(
            db,
            "SELECT * EXCLUDE(path_fields,prefix,vendor) FROM dns_transactions WHERE "
            + where
            + " ORDER BY corrected NULLS LAST,point,frame LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        points = {p.id: p for p in topology.points}
        for row in data:
            row["tooltip"] = TOOLTIP
            row["reason"] = REASONS.get(row["status"]) or (
                "Question/index unsupported, ambiguous response ownership, incomplete deadline coverage or insufficient path/endpoint evidence"
            )
            row["hop"] = (
                row["query_hop"]
                if row["status"] == "query_disappeared"
                else row["response_hop"]
                if row["status"] == "response_disappeared"
                else None
            )
            row["device"] = None
            if row["hop"]:
                _, a, b = row["hop"].split(":")
                row["device"] = points[a].device if points[a].device == points[b].device else None
                row["location"] = row["device"] or f"link between {points[a].label} and {points[b].label}"
            row["evidence"] = evidence(
                db, "o.point=? AND o.frame IN (?,?)", [row["point"], row["frame"], row["response_frame"]], 2
            )
            if row.get("resolver_frame"):
                row["evidence"] += evidence(
                    db, "o.point=? AND o.frame=?", [row["resolver_point"], row["resolver_frame"]], 1
                )
            if row["hop"]:
                row["evidence"] += evidence(
                    db,
                    "o.packet_key=?",
                    [row["packet_key"] if row["status"] == "query_disappeared" else row["far_response_key"]],
                    16,
                )
        return dict(
            items=data,
            total=db.execute("SELECT count(*) FROM dns_transactions WHERE " + where, params).fetchone()[0],
            summary=summary,
            points=[dict(point=p.id, label=p.label, kind=p.kind) for p in topology.points],
            timeout_ms=topology.dns_timeout_ms,
            tooltip=TOOLTIP,
            reason=None,
            note="One complete unicast DNS question/message per indexed frame. Repeated equally plausible attempts are unknown; no nearest-time guess. Local latency is query-to-response turnaround, not isolated resolver processing. Deadline coverage and hop clock uncertainty apply.",
        )
