"""One-to-one application transactions; TCP connections are never merged by this matcher."""

import json
import duckdb
from .store import rows


def pair_requests(clients, servers, window_s, uncertainty_s, declared=True, db=None):
    pending_c = {r["id"]: r for r in clients}
    pending_s = {r["id"]: r for r in servers}
    found = []
    blocked = None if declared else "Boundary is not declared full_proxy"
    if uncertainty_s is None:
        blocked = blocked or "Clock uncertainty unavailable; bounded pairing window unverified"
    candidates = []
    if not blocked:
        schema = '[{"id":"VARCHAR","flow":"VARCHAR","origin_ip":"VARCHAR","line":"VARCHAR","host":"VARCHAR","xff":"VARCHAR[]","sni":"VARCHAR","start":"DOUBLE","complete":"DOUBLE","ready":"BOOLEAN","kind":"VARCHAR"}]'
        connection = db or duckdb.connect()
        try:
            edges = rows(
                connection,
                """WITH clients AS (SELECT unnest(from_json(?,?)) r),servers AS (SELECT unnest(from_json(?,?)) r),
                possible AS (SELECT c.r.id AS c,s.r.id AS s,
                    coalesce(c.r.line=s.r.line AND c.r.host=s.r.host AND c.r.line IS NOT NULL AND c.r.host IS NOT NULL,false) AS identity,
                    coalesce(list_contains(s.r.xff,c.r.origin_ip),false) AS xff,
                    coalesce(c.r.sni=s.r.sni AND c.r.sni IS NOT NULL,false) AS sni,
                    abs(s.r.start-c.r.start) AS distance
                FROM clients c JOIN servers s ON c.r.kind=s.r.kind AND c.r.flow<>s.r.flow
                AND s.r.start BETWEEN c.r.start-? AND c.r.start+?+?
                WHERE c.r.ready AND s.r.ready
                    AND NOT(coalesce(c.r.line<>s.r.line OR c.r.host<>s.r.host,false)
                        AND c.r.line IS NOT NULL AND s.r.line IS NOT NULL AND c.r.host IS NOT NULL AND s.r.host IS NOT NULL)
                    AND (coalesce(len(s.r.xff),0)=0 OR c.r.origin_ip IS NULL OR list_contains(s.r.xff,c.r.origin_ip)))
                SELECT * FROM possible WHERE identity OR xff OR sni LIMIT 50001""",
                [
                    json.dumps(clients),
                    schema,
                    json.dumps(servers),
                    schema,
                    uncertainty_s,
                    window_s,
                    uncertainty_s,
                ],
            )
            if len(edges) > 50000:
                blocked = "More than 50,000 request candidates; narrow the pairing window"
            else:
                for e in edges:
                    candidates.append(
                        dict(
                            c=e["c"],
                            s=e["s"],
                            rank=(e["identity"], e["xff"], e["sni"]),
                            distance=e["distance"],
                        )
                    )
        finally:
            if db is None:
                connection.close()

        def best(edges):
            if not edges:
                return None
            rank = max(e["rank"] for e in edges)
            edges = [e for e in edges if e["rank"] == rank]
            distance = min(e["distance"] for e in edges)
            close = [e for e in edges if e["distance"] - distance <= max(2 * uncertainty_s, 1e-6)]
            return close[0] if len(close) == 1 else None

        rounds = 0
        while pending_c and pending_s and not blocked:
            active = [e for e in candidates if e["c"] in pending_c and e["s"] in pending_s]
            rounds += 1
            if rounds > 100:
                blocked = "Request graph exceeds the 100-round resolution budget"
                break
            by_c = {}
            by_s = {}
            for edge in active:
                by_c.setdefault(edge["c"], []).append(edge)
                by_s.setdefault(edge["s"], []).append(edge)
            winners = []
            for cid in pending_c:
                choice = best(by_c.get(cid, []))
                if choice and best(by_s.get(choice["s"], [])) == choice:
                    winners.append(choice)
            if not winners:
                break
            for e in winners:
                c = pending_c.pop(e["c"])
                s = pending_s.pop(e["s"])
                rank = e["rank"]
                found.append(
                    dict(
                        status="matched",
                        client_id=c["id"],
                        server_id=s["id"],
                        reason=None,
                        evidence_rank="HTTP request line + Host"
                        if rank[0]
                        else "X-Forwarded-For"
                        if rank[1]
                        else "TLS SNI",
                        xff_confirmed=rank[1],
                        timing_delta_s=s["start"] - c["start"],
                    )
                )
    for side, pending in (("client", pending_c), ("server", pending_s)):
        for r in pending.values():
            found.append(
                dict(
                    status="unknown",
                    client_id=r["id"] if side == "client" else None,
                    server_id=r["id"] if side == "server" else None,
                    reason=blocked
                    or r.get("reason")
                    or "No unique compatible one-to-one request candidate inside the pairing window",
                )
            )
    return found
