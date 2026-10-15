import json

from ..evidence import evidence
from ..store import rows
from ..topology import Topology


def label_host_events(events, topology):
    from ..host_path import host_loss_type

    if not topology:
        return
    points = {p.id: p for p in Topology.model_validate(topology).points}
    for item in events:
        kind = host_loss_type(
            points,
            item["point_a"],
            item["point_b"],
            item["kind"],
            item.get("recovery_key") and item.get("is_data"),
        )
        if kind:
            item["recovery_class"] = item["kind"]
            item["kind"] = kind


def flow_page(
    project, offset=0, limit=50, search="", filter_by="", sort="bytes", start=None, end=None, points=None
):
    with project.connect() as db:
        if not project.get(db, "report"):
            return {"total": 0, "items": []}
        clauses, params = ["tuple ILIKE ?"], ["%" + search + "%"]
        if points:
            clauses.append(
                "EXISTS(SELECT 1 FROM obs o WHERE o.flow=flow_summary.flow AND o.point IN ("
                + ",".join("?" for _ in points)
                + ") AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?))"
            )
            params.extend([*points, start, start, end, end])
        if start is not None or end is not None:
            clauses.append(
                "EXISTS(SELECT 1 FROM obs o WHERE o.flow=flow_summary.flow AND (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?))"
            )
            params.extend([start, start, end, end])
        filters = {
            "impactful": "impactful_loss>0",
            "resets": "has_reset",
            "device_drops": "confirmed_device_drop>0",
            "handshakes": "handshake_incomplete",
        }
        if filter_by in filters:
            clauses.append(filters[filter_by])
        order = (
            sort
            if sort
            in (
                "bytes",
                "max_stall_ms",
                "impactful_loss",
                "retrans_observations",
                "start",
                "reset_origin",
                "handshake_rtt_ms",
            )
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
        label_host_events(events, project.get(db, "topology"))
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
        label_host_events(data, project.get(db, "topology"))
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
            text = f"{g['count']} {f['type'].replace('_', ' ')} events in the selected interval."
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
        items.extend(
            f
            for f in (project.get(db, "export_findings") or [])
            if f["id"].startswith(("integrity:", "security:", "media:"))
            and (start is None or f["time_range"][1] >= start)
            and (end is None or f["time_range"][0] < end)
        )
        order = {f["id"]: i for i, f in enumerate(report["findings"])}
        items.sort(key=lambda f: order.get(f["id"], len(order)))
        return dict(items=items)
