"""Single-path and multi-path topology assembly, analysis execution, and confirmation."""

from .groups import (
    _capture_exclusion_reason,
    _default_points,
    _partition_client_groups,
    assemble_multi_path_groups,
)
from .models import Point, Topology
from .order import (
    check_adjacent_mismatch_warnings,
    compare_units,
    isolate_conflicting_clocks,
    query_ttl_and_pair_stats,
)
from .suggest import _device_stem, _infer_client_cidrs, suggest_topology


def _ambiguous(base_model: Topology, reason: str, warnings: list[str], inferences: list[dict] | None = None):
    return dict(
        status="ambiguous",
        ambiguous=True,
        confirmed=False,
        reason=reason,
        topology=base_model.model_dump(),
        inferences=list(inferences or []),
        warnings=warnings,
    )


def _classify_units_and_clocks(
    raw_suggestions: dict,
    ready_ids: list[str],
    ttl_by_cid: dict,
    points_by_cid: dict,
    names: dict[str, str],
    inferences: list[dict],
):
    host_items = [
        s
        for s in raw_suggestions["items"]
        if s["kind"] == "host_capture" and s["capture_ids"][0] in points_by_cid
    ]
    host_cids = set()
    client_host_cids, server_host_cids = [], []
    for item in host_items:
        cid = item["capture_ids"][0]
        host_cids.add(cid)
        tinfo = ttl_by_cid[cid]
        pt = points_by_cid[cid]
        pt.host_capture = True
        pt.stage_capture = False
        pt.side = "both"
        if (tinfo.get("fwd_super") or 0) > (tinfo.get("rev_super") or 0):
            pt.kind = "Client"
            client_host_cids.append(cid)
        else:
            pt.kind = "Server"
            server_host_cids.append(cid)
        inferences.append(item)

    if len(client_host_cids) > 1 or len(server_host_cids) > 1:
        return (
            None,
            None,
            None,
            None,
            "Multiple host offload captures detected on the same endpoint side; assign host order manually.",
        )

    stage_items = [
        s
        for s in raw_suggestions["items"]
        if s["kind"] == "stage_pair"
        and all(cid in points_by_cid and cid not in host_cids for cid in s["capture_ids"])
    ]
    stage_used = set()
    stage_units: list[list[str]] = []
    for item in stage_items:
        rx_cid, tx_cid = item["capture_ids"]
        if rx_cid in stage_used or tx_cid in stage_used:
            continue
        stage_used.update((rx_cid, tx_cid))
        stage_units.append([rx_cid, tx_cid])
        dev = _device_stem(names[rx_cid], names[tx_cid])
        for cid, side in ((rx_cid, "ingress"), (tx_cid, "egress")):
            pt = points_by_cid[cid]
            pt.stage_capture = True
            pt.side = side
            pt.device = dev
            pt.kind = "Firewall"
        inferences.append(item)

    clock_items = [
        s
        for s in raw_suggestions["items"]
        if s["kind"] == "shared_clock"
        and all(cid in points_by_cid and cid not in host_cids for cid in s["capture_ids"])
    ]
    adj: dict[str, set[str]] = {}
    for item in clock_items:
        a, b = item["capture_ids"]
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)
        inferences.append(item)
    visited = set()
    components: list[set[str]] = []
    for cid in ready_ids:
        if cid in adj and cid not in visited:
            comp = set()
            stack = [cid]
            while stack:
                cur = stack.pop()
                if cur in visited:
                    continue
                visited.add(cur)
                comp.add(cur)
                stack.extend(adj.get(cur, ()) - visited)
            if len(comp) >= 2:
                components.append(comp)
    clock_domain_of: dict[str, str] = {}
    for idx, comp in enumerate(sorted(components, key=lambda c: sorted(c)[0])):
        domain_name = "appliance" if len(components) == 1 else f"appliance_{idx + 1}"
        for cid in comp:
            points_by_cid[cid].clock_domain = domain_name
            clock_domain_of[cid] = domain_name
    for cid in host_cids:
        points_by_cid[cid].clock_domain = None

    units: list[list[str]] = list(stage_units)
    for cid in ready_ids:
        if cid not in host_cids and cid not in stage_used:
            pt = points_by_cid[cid]
            pt.stage_capture = False
            pt.side = "both"
            units.append([cid])
    return client_host_cids, server_host_cids, clock_domain_of, units, None


def _assemble_single_topology(
    db, base_model: Topology, captures: list[dict], raw_suggestions: dict, all_captures: list[dict] | None = None
):
    ready_ids = [c["id"] for c in captures]
    ready_set = set(ready_ids)
    names = {c["id"]: c["name"] for c in captures}
    warnings = [
        s["warning"]
        for s in raw_suggestions.get("items", [])
        if s.get("warning") and set(s.get("capture_ids", ())) <= ready_set
    ]
    inferences: list[dict] = []

    if len(captures) < 2:
        return _ambiguous(base_model, "At least two ready captures are required to assemble a path.", warnings)

    all_points_by_cid = _default_points(all_captures or captures, base_model.points)
    points_by_cid = {cid: all_points_by_cid[cid].model_copy(deep=True) for cid in ready_ids}

    client_cidrs, cidr_inference, cidr_err = _infer_client_cidrs(db, names, ready_ids)
    if cidr_err or not client_cidrs:
        excl_reason = _capture_exclusion_reason(db, captures, ready_ids)
        return _ambiguous(
            base_model, excl_reason or cidr_err or "Client direction could not be inferred unambiguously.", warnings
        )
    inferences.append(cidr_inference)
    base_model = base_model.model_copy(update=dict(client_cidrs=client_cidrs))
    client_ips = [cidr.split("/")[0] for cidr in client_cidrs]

    ttl_by_cid, pair_stats = query_ttl_and_pair_stats(db, ready_ids, client_ips)
    missing_cid_ids = [
        cid
        for cid in ready_ids
        if cid not in ttl_by_cid
        or ((ttl_by_cid[cid]["fwd_n"] or 0) == 0 and (ttl_by_cid[cid]["rev_n"] or 0) == 0)
    ]
    if missing_cid_ids:
        excl_reason = _capture_exclusion_reason(db, captures, missing_cid_ids)
        missing_names = [names[cid] for cid in missing_cid_ids]
        msg = excl_reason or f"Capture(s) {', '.join(missing_names)} share no directional TCP traffic with the rest of the folder."
        return _ambiguous(base_model, msg, warnings, inferences)

    client_host_cids, server_host_cids, clock_domain_of, units, host_err = _classify_units_and_clocks(
        raw_suggestions, ready_ids, ttl_by_cid, points_by_cid, names, inferences
    )
    if host_err:
        return _ambiguous(base_model, host_err, warnings, inferences)

    wins = {i: 0 for i in range(len(units))}
    hop_refs: dict[tuple[int, int], list[dict]] = {}
    conflicting_unit_pairs: list[tuple[int, int]] = []
    for i in range(len(units)):
        for j in range(i + 1, len(units)):
            cmp_val, err, refs, us_conflict = compare_units(
                units[i], units[j], ttl_by_cid, clock_domain_of, pair_stats, names
            )
            if cmp_val == 0:
                return _ambiguous(base_model, err or "Path order between captures is ambiguous.", warnings, inferences)
            if us_conflict:
                conflicting_unit_pairs.append((i, j))
            if cmp_val < 0:
                wins[i] += 1
                hop_refs[(i, j)] = refs
            else:
                wins[j] += 1
                hop_refs[(j, i)] = list(reversed(refs)) if refs else []

    if len(set(wins.values())) != len(units):
        return _ambiguous(
            base_model,
            "Pairwise TTL/timestamp comparisons do not form a consistent linear path order.",
            warnings,
            inferences,
        )

    return _finalize_ordered_topology(
        base_model, units, wins, hop_refs, conflicting_unit_pairs, client_host_cids, server_host_cids,
        clock_domain_of, ttl_by_cid, pair_stats, points_by_cid, all_points_by_cid, names, client_cidrs,
        inferences, warnings,
    )


def _finalize_ordered_topology(
    base_model: Topology, units: list[list[str]], wins: dict[int, int], hop_refs: dict[tuple[int, int], list[dict]],
    conflicting_unit_pairs: list[tuple[int, int]], client_host_cids: list[str], server_host_cids: list[str],
    clock_domain_of: dict[str, str], ttl_by_cid: dict[str, dict], pair_stats: dict[tuple[str, str], dict],
    points_by_cid: dict[str, Point], all_points_by_cid: dict[str, Point], names: dict[str, str],
    client_cidrs: list[str], inferences: list[dict], warnings: list[str],
):
    ordered_indices = sorted(range(len(units)), key=lambda idx: -wins[idx])
    ordered_units = [units[idx] for idx in ordered_indices]
    inferences = isolate_conflicting_clocks(
        units, conflicting_unit_pairs, wins, clock_domain_of, points_by_cid, names, warnings, inferences
    )

    if ordered_units and server_host_cids:
        h_cid = server_host_cids[0]
        last_wire = ordered_units[-1][-1]
        hf = ttl_by_cid[h_cid]["fwd_ttl"]
        wf = ttl_by_cid[last_wire]["fwd_ttl"]
        if hf is not None and wf is not None and hf > wf:
            return dict(
                status="ambiguous",
                ambiguous=True,
                confirmed=False,
                reason=f"Host capture {names[h_cid]} has higher forward TTL ({hf}) than wire capture {names[last_wire]} ({wf}).",
                topology=base_model.model_dump(),
                inferences=inferences,
                warnings=warnings,
            )

    forward_cids = client_host_cids + [cid for u in ordered_units for cid in u] + server_host_cids
    reverse_cids = (
        list(reversed(server_host_cids))
        + [cid for u in reversed(ordered_units) for cid in u]
        + list(reversed(client_host_cids))
    )
    check_adjacent_mismatch_warnings(ordered_indices, units, pair_stats, names, warnings)

    path_evidence = []
    for idx_a, idx_b in zip(ordered_indices, ordered_indices[1:]):
        for ref in hop_refs.get((idx_a, idx_b), []):
            if ref not in path_evidence:
                path_evidence.append(ref)
    if not path_evidence:
        for cid in forward_cids[:2]:
            fr = ttl_by_cid[cid]["fwd_frame"] or ttl_by_cid[cid]["rev_frame"]
            if fr:
                path_evidence.append(
                    dict(capture_id=cid, file=names[cid], frame=fr, display_filter=f"frame.number == {fr}")
                )

    ordered_points = []
    for pos, cid in enumerate(forward_cids):
        pt = points_by_cid[cid]
        pt.x = pos * 220
        pt.y = 120
        ordered_points.append(pt)
    for cid, pt in all_points_by_cid.items():
        if cid not in forward_cids:
            ordered_points.append(pt.model_copy(deep=True))

    inferences.append(
        dict(
            kind="path_order",
            capture_ids=forward_cids,
            forward=[points_by_cid[cid].id for cid in forward_cids],
            reverse=[points_by_cid[cid].id for cid in reverse_cids],
            metrics=dict(
                forward_labels=[points_by_cid[cid].label for cid in forward_cids],
                reverse_labels=[points_by_cid[cid].label for cid in reverse_cids],
                forward_ttls={points_by_cid[cid].label: ttl_by_cid[cid]["fwd_ttl"] for cid in forward_cids},
                reverse_ttls={points_by_cid[cid].label: ttl_by_cid[cid]["rev_ttl"] for cid in forward_cids},
            ),
            evidence=path_evidence[:8],
            reason="Forward and reverse path order assembled from TTL steps, microsecond transit deltas and host offload boundary.",
        )
    )

    assembled = base_model.model_copy(
        update=dict(
            points=ordered_points,
            forward=[points_by_cid[cid].id for cid in forward_cids],
            reverse=[points_by_cid[cid].id for cid in reverse_cids],
            client_cidrs=client_cidrs,
        )
    )
    return dict(
        status="ready",
        ambiguous=False,
        confirmed=False,
        badge="Suggested topology — review & confirm",
        reason="Suggested topology assembled from stage pairs, shared clock domains, TTL steps, microsecond ordering and host offload evidence.",
        topology=assembled.model_dump(),
        inferences=inferences,
        warnings=warnings,
    )


def assemble_topology(project, base_topology: Topology | dict | None = None):
    raw_suggestions = suggest_topology(project)
    warnings = list(raw_suggestions.get("warnings", []))

    all_captures = project.inventory()
    captures = [c for c in all_captures if c["state"] == "ready"]
    with project.connect() as db:
        if base_topology is None:
            saved = project.get(db, "topology")
            base_model = Topology.model_validate(saved) if saved else Topology()
        elif isinstance(base_topology, Topology):
            base_model = base_topology.model_copy(deep=True)
        else:
            base_model = Topology.model_validate(base_topology)

        early_exclusion = _capture_exclusion_reason(db, all_captures)
        if early_exclusion:
            return dict(
                status="ambiguous",
                ambiguous=True,
                confirmed=False,
                reason=early_exclusion,
                topology=base_model.model_dump(),
                inferences=[],
                warnings=warnings,
            )

        group_cid_lists = _partition_client_groups(db, captures, raw_suggestions)
        if group_cid_lists and len(group_cid_lists) >= 2:
            return assemble_multi_path_groups(
                db, base_model, captures, raw_suggestions, group_cid_lists, warnings, _assemble_single_topology
            )

        res = _assemble_single_topology(db, base_model, captures, raw_suggestions, all_captures=captures)
        for w in warnings:
            if w not in res["warnings"]:
                res["warnings"].insert(0, w)
        return res


def assemble_and_analyze(project, base_topology=None, progress=None, cancel=None):
    from ..analysis import analyze

    with project.connect() as db:
        current = project.get(db, "topology")
        if current and not project.get(db, "unconfirmed_topology"):
            project.set(db, "unconfirmed_topology", current)
    assembly = assemble_topology(project, base_topology=base_topology)
    with project.connect() as db:
        project.set(db, "suggested_topology", assembly)
    if assembly["ambiguous"]:
        return dict(suggested_topology=assembly, report=None)
    if assembly.get("groups") and len(assembly["groups"]) >= 2:
        for g in reversed(assembly["groups"]):
            if g.get("ambiguous"):
                g["report"] = None
                continue
            g_report = analyze(project, g["topology"], progress=progress, cancel=cancel)
            g_meta = {k: v for k, v in g.items() if k != "report"}
            g_report["suggested_topology"] = g_meta
            g["report"] = g_report
        ready_groups = [g for g in assembly["groups"] if not g.get("ambiguous") and g.get("report")]
        group_reports = {g["name"]: dict(g["report"]) for g in ready_groups}
        primary_report = {
            **ready_groups[0]["report"],
            "suggested_topology": assembly,
            "group_reports": group_reports,
        }
        with project.connect() as db:
            project.set(db, "topology", ready_groups[0]["topology"])
            project.set(db, "report", primary_report)
            project.set(db, "suggested_topology", assembly)
        return dict(suggested_topology=assembly, report=primary_report, groups=assembly["groups"])
    report = analyze(project, assembly["topology"], progress=progress, cancel=cancel)
    report["suggested_topology"] = assembly
    with project.connect() as db:
        project.set(db, "report", report)
        project.set(db, "suggested_topology", assembly)
    return dict(suggested_topology=assembly, report=report)


def confirm_suggested_topology(project, group: str | None = None):
    with project.connect() as db:
        suggested = project.get(db, "suggested_topology")
        if not suggested or suggested.get("ambiguous"):
            raise ValueError("No assembled suggested topology is pending confirmation")
        if suggested.get("groups"):
            groups = [dict(g) for g in suggested["groups"]]
            if group is not None:
                matched = [g for g in groups if g["name"] == group]
                if not matched:
                    raise ValueError(f"Unknown suggested topology group: {group}")
                if matched[0].get("ambiguous"):
                    raise ValueError(f"Suggested topology group {group} is ambiguous")
                target_names = {group}
            else:
                target_names = {g["name"] for g in groups if not g.get("ambiguous")}
            for g in groups:
                if g["name"] in target_names:
                    g["confirmed"] = True
                    if g.get("report") and isinstance(g["report"].get("suggested_topology"), dict):
                        g["report"] = {
                            **g["report"],
                            "suggested_topology": {**g["report"]["suggested_topology"], "confirmed": True},
                        }
            ready_groups = [g for g in groups if not g.get("ambiguous")]
            all_confirmed = bool(ready_groups) and all(g.get("confirmed") for g in ready_groups)
            suggested = {**suggested, "groups": groups, "confirmed": all_confirmed}
            if group is not None:
                chosen = next(g for g in groups if g["name"] == group)
                suggested["topology"] = chosen["topology"]
                suggested["inferences"] = chosen["inferences"]
                project.set(db, "topology", chosen["topology"])
                if chosen.get("report"):
                    rep = {
                        **chosen["report"],
                        "suggested_topology": suggested,
                        "group_reports": {g["name"]: dict(g["report"]) for g in groups if g.get("report")},
                    }
                    project.set(db, "report", rep)
        else:
            suggested = {**suggested, "confirmed": True}
        project.set(db, "suggested_topology", suggested)
        if suggested.get("confirmed"):
            project.set(db, "unconfirmed_topology", None)
        report = project.get(db, "report")
        if report:
            report = {**report, "suggested_topology": suggested}
            if suggested.get("groups"):
                report["group_reports"] = {
                    g["name"]: dict(g["report"]) for g in suggested["groups"] if g.get("report")
                }
            project.set(db, "report", report)
        return suggested
