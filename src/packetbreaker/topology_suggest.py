"""Read-only suggestions; no topology or clock setting changes without confirmation."""

from .store import rows


def suggest_topology(project):
    with project.connect() as db:
        names = dict(db.execute("SELECT id,name FROM captures").fetchall())
        pairs = rows(
            db,
            """WITH unique_packets AS(SELECT *,tuple_key<reverse_tuple AS direction FROM packets
            WHERE proto='TCP' QUALIFY count(*) OVER(PARTITION BY capture_id,tuple_key,signature)=1),
            paired AS(SELECT a.capture_id AS a,b.capture_id AS b,a.direction,(b.ts-a.ts)*1e6 AS delta,a.ttl-b.ttl AS ttl,
                a.frame AS frame_a,b.frame AS frame_b FROM unique_packets a JOIN unique_packets b USING(tuple_key,signature)
                WHERE a.capture_id<b.capture_id), med AS(SELECT a,b,direction,count(*) AS n,median(delta) AS us,
                quantile_cont(delta,.95)-quantile_cont(delta,.05) AS spread_us,median(ttl) AS ttl,
                arg_min(frame_a,abs(delta)) AS frame_a,arg_min(frame_b,abs(delta)) AS frame_b
                FROM paired GROUP BY a,b,direction)
            SELECT a,b,min(n) AS samples,list(us ORDER BY direction) AS deltas_us,max(spread_us) AS spread_us,
                list(ttl ORDER BY direction) AS ttl_steps,min(frame_a) AS frame_a,min(frame_b) AS frame_b
            FROM med GROUP BY a,b HAVING count(*)=2 AND min(n)>=3 AND max(abs(us))<=500 AND max(spread_us)<=500
            ORDER BY spread_us LIMIT 200""",
        )
        items = []
        for p in pairs:
            refs = [
                dict(
                    capture_id=p[k],
                    file=names[p[k]],
                    frame=p["frame_" + k],
                    display_filter=f"frame.number == {p['frame_' + k]}",
                )
                for k in ("a", "b")
            ]
            items.append(
                dict(
                    kind="shared_clock",
                    capture_ids=[p["a"], p["b"]],
                    metrics=p,
                    evidence=refs,
                    reason="Consistent microsecond-scale deltas in both tuple directions; small clock offset remains indistinguishable from transit. Confirm the source clock.",
                )
            )
            sign = (
                1
                if min(p["deltas_us"]) >= 0 and p["ttl_steps"] == [1, 1]
                else -1
                if max(p["deltas_us"]) <= 0 and p["ttl_steps"] == [-1, -1]
                else 0
            )
            if sign:
                ids = [p["a"], p["b"]] if sign > 0 else [p["b"], p["a"]]
                items.append(
                    dict(
                        kind="stage_pair",
                        capture_ids=ids,
                        metrics=p,
                        evidence=refs,
                        reason="Same rx→tx order in both directions, one TTL step and microsecond-scale transit. Confirm one device.",
                    )
                )
        hosts = rows(
            db,
            """SELECT capture_id,count(*) FILTER(WHERE length>1500) AS superframes,
            min(frame) FILTER(WHERE length>1500 AND ttl IN(64,128)) AS frame,max(length) AS max_tcp_bytes
            FROM packets WHERE proto='TCP' GROUP BY capture_id HAVING superframes>0 AND frame IS NOT NULL""",
        )
        for h in hosts:
            items.append(
                dict(
                    kind="host_capture",
                    capture_ids=[h["capture_id"]],
                    metrics=h,
                    evidence=[
                        dict(
                            capture_id=h["capture_id"],
                            file=names[h["capture_id"]],
                            frame=h["frame"],
                            display_filter=f"frame.number == {h['frame']}",
                        )
                    ],
                    reason="TCP super-frames and a 64/128 source TTL suggest host offload. Virtual/middlebox captures can look similar; confirmation required.",
                )
            )
        return dict(
            items=items,
            requires_confirmation=True,
            note="Suggestions do not alter the saved topology. NAT/translation without shared unique packet identities remains unknown.",
        )
