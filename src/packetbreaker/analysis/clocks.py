from dataclasses import replace
import json

from ..clock import ClockModel, fit_clock, infer_shared_clock
from ..evidence import evidence


def clock_range_candidates(db, a, b):
    """Header-only calibration fallback; equal cardinality prevents retry rank shifting."""
    return db.execute(
        """WITH ranked AS (
        SELECT point,frame,ts,flow,direction,seq,ack,flags,
        row_number() OVER(PARTITION BY point,flow,direction,seq,ack,flags ORDER BY ts,frame) AS occurrence,
        count(*) OVER(PARTITION BY point,flow,direction,seq,ack,flags) AS n
        FROM obs WHERE point IN (?,?) AND eligible AND proto='TCP'), paired AS(
        SELECT a.ts AS time_a,b.ts AS time_b,a.direction='forward' AS forward,a.frame AS frame_a,b.frame AS frame_b
        FROM ranked a JOIN ranked b USING(flow,direction,seq,ack,flags,occurrence,n)
        WHERE a.point=? AND b.point=? AND a.direction<>'unknown')
        SELECT * FROM paired ORDER BY hash(frame_a,frame_b),frame_a,frame_b LIMIT 20000""",
        [a, b, a, b],
    ).fetchall()


def _inherit_domains(groups, models, topology, ref):
    for name, members in groups.items():
        known = next(
            (
                models[cid]
                for cid in sorted(members, key=lambda c: (c not in topology.clock_overrides, c != ref, c))
                if cid in models and models[cid].offset is not None
            ),
            None,
        )
        if known is not None:
            for cid in members:
                models[cid] = replace(
                    known,
                    source_domain=name,
                    confidence="declared_shared",
                    reason="User-declared shared appliance clock; no relative fitting",
                )


def _calibrate_pair(db, topology, points, models, a, b):
    aid, cid = points[a].capture_id, points[b].capture_id
    data = db.execute(
        """SELECT a.ts,b.ts,a.direction='forward',a.frame,b.frame
        FROM calibration a JOIN calibration b USING(packet_key) WHERE a.point=? AND b.point=?
        AND a.eligible AND b.eligible AND a.direction<>'unknown'
        ORDER BY hash(a.frame,b.frame),a.frame,b.frame LIMIT 20000""",
        [a, b],
    ).fetchall()
    if (points[a].host_capture or points[b].host_capture or points[b].kind == "Server") and (
        len(data) < 6 or len({r[2] for r in data}) < 2
    ):
        data = clock_range_candidates(db, a, b)
    forward_before = topology.precedes(a, b, "forward")
    reverse_before = topology.precedes(a, b, "reverse")
    shared_bound = None
    if (
        any(abs(y - x) <= 0.0005 for x, y, _, _, _ in data)
        and not points[a].host_capture
        and not points[b].host_capture
        and not points[a].clock_domain
        and not points[b].clock_domain
    ):
        shared_bound = infer_shared_clock(
            [
                (
                    x,
                    x + (y - x) * (1 if (forward_before if f else reverse_before) == f else -1),
                    f,
                )
                for x, y, f, _, _ in data
            ]
        )
    if shared_bound is not None:
        models[cid] = replace(
            models[aid],
            source_domain=models[aid].source_domain or aid,
            uncertainty=max(models[aid].uncertainty, shared_bound)
            if models[aid].uncertainty is not None
            else None,
            confidence="inferred_shared",
            reason="Consistent near-zero positive transit in both directions; shared clock inferred, small offset remains indistinguishable from transit",
        )
        models[cid].samples = len(data)
        models[cid].evidence = []
        for forward in (True, False):
            sample = next((r for r in data if r[2] == forward), None)
            if sample:
                models[cid].evidence.extend(
                    evidence(
                        db,
                        "(o.point=? AND o.frame=?) OR(o.point=? AND o.frame=?)",
                        [a, sample[3], b, sample[4]],
                        2,
                    )
                )
        return True
    model = fit_clock(
        [
            (models[aid].correct(x), y, (forward_before if f else reverse_before))
            for x, y, f, _, _ in data
        ]
    )
    if model.offset is None and (cid not in models or model.samples > models[cid].samples):
        models[cid] = model
    if model.offset is not None:
        model.domain = models[aid].domain
        model.uncertainty = (
            (model.uncertainty or 0) + models[aid].uncertainty
            if models[aid].uncertainty is not None
            else None
        )
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
        return True
    return False


def _apply_fortinet_and_jitter(db, topology, models, ref):
    # Files split from one Fortinet transcript share an actual source clock.
    groups = {}
    for cid, raw in db.execute("SELECT id,inventory FROM captures").fetchall():
        source = json.loads(raw).get("source_metadata") or {}
        if cid in models and source.get("adapter") == "fortinet":
            groups.setdefault(source.get("clock_group", cid), []).append((cid, source))
    for group in groups.values():
        known = next((models[cid] for cid, _ in group if models[cid].offset is not None), None)
        for cid, source in group:
            if known is not None:
                models[cid] = replace(
                    known, reason="Interfaces split from one Fortinet text clock", confidence="shared_source"
                )
            if source.get("clock_confidence") == "low":
                models[cid].confidence = "low"
                models[cid].uncertainty = None
                models[cid].reason = "Relative Fortinet timestamps anchored by a user-supplied start time"
    # Relative adjacent timestamp differences bound jitter without absorbing sparse host-delay events.
    for cid, model in models.items():
        if (
            model.offset is None
            or cid == ref
            or not any(p.stage_capture or p.clock_domain or p.host_capture for p in topology.points)
        ):
            continue
        noise = db.execute(
            """WITH pairs AS(SELECT b.ts-a.ts AS delta,a.ts,
            lag(b.ts-a.ts) OVER(PARTITION BY a.point,b.point,a.direction ORDER BY a.ts,a.frame,b.frame) AS previous
            FROM calibration a JOIN calibration b USING(packet_key) WHERE a.capture_id=? AND b.capture_id=? AND a.eligible AND b.eligible)
            SELECT least(.002,coalesce(quantile_cont(abs(delta-previous),.5),0)*4) FROM pairs""",
            [ref, cid],
        ).fetchone()[0]
        model.timestamp_jitter = max(model.timestamp_jitter, noise)


def align(db, topology):
    points = {p.id: p for p in topology.points}
    order = list(
        dict.fromkeys(
            topology.forward + topology.reverse + [p.id for p in topology.points if p.vendor == "paloalto"]
        )
    )
    groups = {}
    for p in topology.points:
        if p.clock_domain:
            groups.setdefault(p.clock_domain, set()).add(p.capture_id)

    models = {}
    ref = points[order[0]].capture_id
    epoch = db.execute("SELECT min(ts) FROM obs WHERE capture_id=?", [ref]).fetchone()[0] or 0
    models[ref] = ClockModel(0, 0, epoch, 0, "reference", "Reference capture clock", 0)
    models[ref].domain = ref
    for cid, override in topology.clock_overrides.items():
        models[cid] = ClockModel(
            override.offset_ms / 1000,
            override.drift_ppm / 1e6,
            epoch,
            None,
            "override",
            "User-supplied clock correction; uncertainty unverified",
            domain=ref,
        )
    _inherit_domains(groups, models, topology, ref)
    # Multiple passes permit an asymmetric return-path point to calibrate against any known point.
    for _ in range(len(order)):
        changed = False
        for b in order:
            cid = points[b].capture_id
            if cid in models and models[cid].offset is not None:
                continue
            for a in sorted(order, key=lambda point: abs(order.index(point) - order.index(b))):
                aid = points[a].capture_id
                if aid not in models or models[aid].offset is None:
                    continue
                if _calibrate_pair(db, topology, points, models, a, b):
                    _inherit_domains(groups, models, topology, ref)
                    changed = True
                    break
        if not changed:
            if any(p.translation == "full_proxy" for p in topology.points):
                # Calibrate disconnected TCP legs locally, without asserting cross-proxy clock alignment.
                missing = next(
                    (
                        points[p].capture_id
                        for p in order
                        if points[p].capture_id not in models or models[points[p].capture_id].offset is None
                    ),
                    None,
                )
                if missing:
                    local_epoch = db.execute(
                        "SELECT min(ts) FROM obs WHERE capture_id=?", [missing]
                    ).fetchone()[0]
                    if local_epoch is not None:
                        models[missing] = ClockModel(
                            0,
                            0,
                            local_epoch,
                            0,
                            "reference",
                            "Independent TCP leg reference; cross-domain timing unknown",
                            domain=missing,
                        )
                        continue
            break
    for p in order:
        models.setdefault(points[p].capture_id, ClockModel(epoch=epoch))
    # A disconnected declared domain still has valid relative clocks inside the group.
    for name, members in groups.items():
        if not any(models[c].offset is not None for c in members if c in models):
            anchor = min(members)
            models[anchor] = ClockModel(
                0,
                0,
                epoch,
                0,
                "declared_shared",
                "Independent declared clock domain; cross-domain timing unknown",
                domain="shared:" + name,
                source_domain=name,
            )
    _inherit_domains(groups, models, topology, ref)
    _apply_fortinet_and_jitter(db, topology, models, ref)
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
