"""Multi-path client group partitioning, default point layout, and capture exclusion reasons."""

from pathlib import Path
import re

from ..store import rows
from .models import Point, Topology


def _default_points(captures, existing_points=None):
    by_cid = {p.capture_id: p.model_copy(deep=True) for p in (existing_points or []) if p.capture_id}
    stems = [re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(c["name"]).stem).strip("_") for c in captures]
    unique_stems = len(set(stems)) == len(captures) and all(stems)
    result = {}
    for i, c in enumerate(captures):
        cid = c["id"]
        if cid in by_cid:
            pt = by_cid[cid]
            if unique_stems and pt.id == "p_" + cid and "/" not in pt.label:
                pt.id = stems[i]
                pt.label = stems[i]
                if pt.device == c["name"]:
                    pt.device = stems[i]
            result[cid] = pt
        else:
            pid = stems[i] if unique_stems else f"p_{cid}"
            label = stems[i] if unique_stems else c["name"][:100]
            result[cid] = Point(
                id=pid,
                label=label,
                device=label,
                capture_id=cid,
                x=(i % 4) * 240,
                y=(i // 4) * 180,
            )
    return result


def _capture_exclusion_reason(db, captures, candidate_ids=None) -> str | None:
    by_id = {c["id"]: c for c in captures if c.get("id")}
    check_ids = candidate_ids if candidate_ids is not None else [c["id"] for c in captures if c.get("id")]
    empty_msgs = []
    mostly_excluded_msgs = []
    for cid in check_ids:
        c = by_id.get(cid)
        if not c:
            continue
        name = c["name"]
        inv = c.get("inventory") or {}
        prefilter_excluded = int(inv.get("prefilter_excluded") or 0)
        ts_excluded = sum(int(v) for v in (inv.get("timestamp_excluded_counts") or {}).values())
        row = db.execute("SELECT count(*) FROM packets WHERE capture_id=?", [cid]).fetchone()
        total_packets = int(row[0] or 0)
        uniq_row = db.execute(
            """SELECT count(*) FROM (
                   SELECT 1 FROM packets
                   WHERE capture_id=? AND proto='TCP' AND (unsupported IS NULL OR unsupported='')
                   GROUP BY tuple_key, signature HAVING count(*)=1
               )""",
            [cid],
        ).fetchone()
        unique_tcp = int(uniq_row[0] or 0)
        non_matchable = total_packets - unique_tcp
        excluded_total = prefilter_excluded + ts_excluded + non_matchable
        raw_total = max(int(inv.get("prefilter_total") or 0), prefilter_excluded + ts_excluded + total_packets)
        if total_packets == 0 or c.get("state") == "error":
            if prefilter_excluded > 0:
                empty_msgs.append(f"{name} is empty ({prefilter_excluded} of {raw_total} frames excluded by pre-filter)")
            elif ts_excluded > 0:
                empty_msgs.append(f"{name} is empty ({ts_excluded} frames excluded due to invalid timestamps)")
            else:
                empty_msgs.append(f"{name} is empty (0 usable frames)")
        elif candidate_ids is not None or unique_tcp == 0:
            if raw_total > 0 and (unique_tcp == 0 or excluded_total > unique_tcp):
                mostly_excluded_msgs.append(
                    f"{name} is mostly excluded ({excluded_total} of {raw_total} frames excluded; {unique_tcp} usable TCP frame(s) remain)"
                )
    if empty_msgs:
        return f"Capture(s) {'; '.join(empty_msgs)}; path order is ambiguous."
    if mostly_excluded_msgs:
        return f"Capture(s) {'; '.join(mostly_excluded_msgs)}; path order is ambiguous."
    return None


def _partition_client_groups(db, captures, raw_suggestions) -> list[list[str]] | None:
    ready_ids = [c["id"] for c in captures]
    host_cids = {
        s["capture_ids"][0]
        for s in raw_suggestions.get("items", [])
        if s["kind"] == "host_capture" and s["capture_ids"][0] in ready_ids
    }
    non_host_cids = [cid for cid in ready_ids if cid not in host_cids]
    if not host_cids or len(non_host_cids) < 2:
        return None

    placeholders = ",".join("?" for _ in ready_ids)
    flow_rows = rows(
        db,
        f"""WITH shared_flows AS (
            SELECT least(tuple_key, reverse_tuple) AS canon
            FROM packets
            WHERE capture_id IN ({placeholders}) AND proto='TCP' AND (unsupported IS NULL OR unsupported='')
            GROUP BY 1 HAVING count(DISTINCT capture_id) >= 2
        )
        SELECT DISTINCT p.capture_id, sf.canon
        FROM packets p
        JOIN shared_flows sf ON least(p.tuple_key, p.reverse_tuple) = sf.canon
        WHERE p.capture_id IN ({placeholders}) AND p.proto='TCP'
          AND (p.unsupported IS NULL OR p.unsupported='')""",
        [*ready_ids, *ready_ids],
    )
    flows_by_cid: dict[str, set[str]] = {cid: set() for cid in ready_ids}
    for r in flow_rows:
        flows_by_cid[r["capture_id"]].add(r["canon"])

    if any(not flows_by_cid[cid] for cid in non_host_cids):
        return None

    adj: dict[str, set[str]] = {cid: set() for cid in non_host_cids}
    for i, a in enumerate(non_host_cids):
        for b in non_host_cids[i + 1 :]:
            if flows_by_cid[a] & flows_by_cid[b]:
                adj[a].add(b)
                adj[b].add(a)

    visited: set[str] = set()
    components: list[list[str]] = []
    for cid in non_host_cids:
        if cid in visited:
            continue
        comp_set: set[str] = set()
        stack = [cid]
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            comp_set.add(cur)
            stack.extend(adj[cur] - visited)
        components.append([c for c in non_host_cids if c in comp_set])

    if len(components) < 2:
        return None

    group_cid_lists: list[list[str]] = []
    for comp in components:
        comp_flows = set().union(*(flows_by_cid[c] for c in comp))
        shared_hosts = [h for h in ready_ids if h in host_cids and (comp_flows & flows_by_cid[h])]
        if not shared_hosts:
            return None
        comp_ids = set(comp) | set(shared_hosts)
        group_cid_lists.append([cid for cid in ready_ids if cid in comp_ids])

    return group_cid_lists


def assemble_multi_path_groups(
    db,
    base_model: Topology,
    captures: list[dict],
    raw_suggestions: dict,
    group_cid_lists: list[list[str]],
    warnings: list[str],
    assemble_single_fn,
):
    by_cid = {c["id"]: c for c in captures}
    host_cids = {
        s["capture_ids"][0]
        for s in raw_suggestions.get("items", [])
        if s["kind"] == "host_capture" and s["capture_ids"][0] in by_cid
    }
    groups = []
    seen_cidrs: set[str] = set()
    combined_warnings = list(warnings)
    for g_cids in group_cid_lists:
        g_captures = [by_cid[cid] for cid in g_cids]
        g_res = assemble_single_fn(
            db, base_model, g_captures, raw_suggestions, all_captures=captures
        )
        for w in g_res.get("warnings", []):
            if w not in combined_warnings:
                combined_warnings.append(w)
        g_cidrs = g_res["topology"].get("client_cidrs") or []
        if seen_cidrs & set(g_cidrs):
            return dict(
                status="ambiguous",
                ambiguous=True,
                confirmed=False,
                reason=f"Disconnected capture groups share client CIDR(s) {sorted(seen_cidrs & set(g_cidrs))}; path order between them is ambiguous.",
                topology=base_model.model_dump(),
                inferences=g_res.get("inferences", []),
                warnings=combined_warnings,
            )
        seen_cidrs.update(g_cidrs)
        group_name = (
            ", ".join(g_cidrs)
            if g_cidrs
            else ", ".join(by_cid[cid]["name"] for cid in g_cids if cid not in host_cids)
        )
        groups.append(
            dict(
                name=group_name,
                client_cidrs=g_cidrs,
                capture_ids=g_cids,
                status=g_res["status"],
                ambiguous=bool(g_res["ambiguous"]),
                confirmed=False,
                badge="Suggested topology ambiguous — manual input required"
                if g_res["ambiguous"]
                else "Suggested topology — review & confirm",
                reason=g_res["reason"],
                topology=g_res["topology"],
                inferences=g_res.get("inferences", []),
                warnings=g_res.get("warnings", []),
            )
        )
    groups.sort(key=lambda g: g["name"])
    ready_groups = [g for g in groups if not g["ambiguous"]]
    if not ready_groups:
        return dict(
            status="ambiguous",
            ambiguous=True,
            confirmed=False,
            multi_path=True,
            reason="; ".join(f"{g['name']}: {g['reason']}" for g in groups),
            topology=base_model.model_dump(),
            inferences=[],
            warnings=combined_warnings,
            groups=groups,
        )
    return dict(
        status="ready",
        ambiguous=False,
        confirmed=False,
        multi_path=True,
        badge="Suggested topology — review & confirm",
        reason=f"Assembled {len(ready_groups)} of {len(groups)} independent client paths ({', '.join(g['name'] for g in ready_groups)}) sharing host capture.",
        topology=ready_groups[0]["topology"],
        inferences=ready_groups[0]["inferences"],
        warnings=combined_warnings,
        groups=groups,
    )
