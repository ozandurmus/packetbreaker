"""Read-only suggestions and explicit review-and-confirm topology auto-assembly."""

from pathlib import Path
import re

from .store import rows
from .topology import Point, Topology

INGRESS_TOKENS = {"in", "rx", "ingress", "inside", "recv", "receive"}
EGRESS_TOKENS = {"out", "tx", "egress", "outside", "send", "transmit"}


def _name_direction(name: str) -> str | None:
    stem = Path(name).stem.lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", stem) if t]
    has_in = any(t in INGRESS_TOKENS or (len(t) > 2 and t.endswith(("rx", "ingress"))) for t in tokens)
    has_out = any(t in EGRESS_TOKENS or (len(t) > 2 and t.endswith(("tx", "egress"))) for t in tokens)
    if has_in and not has_out:
        return "ingress"
    if has_out and not has_in:
        return "egress"
    return None


def _device_stem(name_a: str, name_b: str) -> str:
    def clean(name: str) -> list[str]:
        stem = Path(name).stem
        tokens = [t for t in re.split(r"[^A-Za-z0-9]+", stem) if t]
        return [
            t
            for t in tokens
            if t.lower() not in (INGRESS_TOKENS | EGRESS_TOKENS) and not re.fullmatch(r"case\d*", t.lower())
        ]

    ta, tb = clean(name_a), clean(name_b)
    common = []
    for x, y in zip(ta, tb):
        if x.lower() == y.lower():
            common.append(x)
        else:
            break
    base = "_".join(common) if common else ("_".join(ta) or Path(name_a).stem)
    return base.upper() if len(base) == 1 else base


def _mismatch_warning(name_ingress_observed: str, name_egress_observed: str) -> str | None:
    dir_in = _name_direction(name_ingress_observed)
    dir_out = _name_direction(name_egress_observed)
    if dir_out == "ingress" and dir_in != "ingress":
        return (
            f"File names suggest {name_egress_observed} -> {name_ingress_observed}, "
            f"packets show {name_ingress_observed} -> {name_egress_observed} "
            f"(names may describe interfaces, not direction)"
        )
    return None


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
        warnings = []
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
                ordered_refs = refs if sign > 0 else list(reversed(refs))
                warn = _mismatch_warning(names[ids[0]], names[ids[1]])
                if warn and warn not in warnings:
                    warnings.append(warn)
                stage_item = dict(
                    kind="stage_pair",
                    capture_ids=ids,
                    metrics=p,
                    evidence=ordered_refs,
                    reason="Same rx→tx order in both directions, one TTL step and microsecond-scale transit. Confirm one device.",
                )
                if warn:
                    stage_item["warning"] = warn
                items.append(stage_item)
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
            warnings=warnings,
            requires_confirmation=True,
            note="Suggestions do not alter the saved topology. NAT/translation without shared unique packet identities remains unknown.",
        )


def _infer_client_cidrs(db, names, ready_ids):
    placeholders = ",".join("?" for _ in ready_ids)
    syn_rows = rows(
        db,
        f"""WITH shared_flows AS (
            SELECT least(tuple_key, reverse_tuple) AS canon
            FROM packets
            WHERE capture_id IN ({placeholders}) AND proto='TCP' AND (unsupported IS NULL OR unsupported='')
            GROUP BY 1 HAVING count(DISTINCT capture_id) >= 2
        )
        SELECT p.capture_id, p.frame, p.src, p.dst, p.sport, p.dport, p.flags
        FROM packets p
        JOIN shared_flows sf ON least(p.tuple_key, p.reverse_tuple) = sf.canon
        WHERE p.capture_id IN ({placeholders}) AND p.proto='TCP'
          AND (p.unsupported IS NULL OR p.unsupported='')
          AND (p.flags & 18) IN (2, 18)
        ORDER BY p.ts, p.frame""",
        [*ready_ids, *ready_ids],
    )
    if syn_rows:
        client_ips, server_ips = set(), set()
        for r in syn_rows:
            if (r["flags"] & 18) == 2:
                client_ips.add(r["src"])
                server_ips.add(r["dst"])
            else:
                client_ips.add(r["dst"])
                server_ips.add(r["src"])
        if client_ips and not (client_ips & server_ips):
            cidrs = [f"{ip}/128" if ":" in ip else f"{ip}/32" for ip in sorted(client_ips)]
            first = syn_rows[0]
            ref = dict(
                capture_id=first["capture_id"],
                file=names[first["capture_id"]],
                frame=first["frame"],
                display_filter=f"frame.number == {first['frame']}",
            )
            return (
                cidrs,
                dict(
                    kind="client_cidrs",
                    method="syn_direction",
                    capture_ids=[first["capture_id"]],
                    client_cidrs=cidrs,
                    metrics=dict(
                        method="syn_direction",
                        client_ips=sorted(client_ips),
                        server_ips=sorted(server_ips),
                        handshake_observations=len(syn_rows),
                    ),
                    evidence=[ref],
                    reason=f"Client CIDR(s) {', '.join(cidrs)} inferred from TCP SYN/SYN-ACK direction.",
                ),
                None,
            )

    flow_rows = rows(
        db,
        f"""WITH shared_flows AS (
            SELECT least(tuple_key, reverse_tuple) AS canon
            FROM packets
            WHERE capture_id IN ({placeholders}) AND proto='TCP' AND (unsupported IS NULL OR unsupported='')
            GROUP BY 1 HAVING count(DISTINCT capture_id) >= 2
        ),
        flow_exemplars AS (
            SELECT least(p.tuple_key, p.reverse_tuple) AS canon,
                   arg_min(p.capture_id, p.ts) AS capture_id,
                   arg_min(p.frame, p.ts) AS frame,
                   arg_min(p.src, p.ts) AS src,
                   arg_min(p.dst, p.ts) AS dst,
                   arg_min(p.sport, p.ts) AS sport,
                   arg_min(p.dport, p.ts) AS dport
            FROM packets p
            JOIN shared_flows sf ON least(p.tuple_key, p.reverse_tuple) = sf.canon
            WHERE p.capture_id IN ({placeholders}) AND p.proto='TCP'
              AND (p.unsupported IS NULL OR p.unsupported='')
            GROUP BY 1
        )
        SELECT * FROM flow_exemplars ORDER BY canon""",
        [*ready_ids, *ready_ids],
    )
    if not flow_rows:
        return [], None, "No shared TCP flows observed across at least two captures."

    endpoint_peers: dict[tuple[str, int], set[tuple[str, int]]] = {}
    for r in flow_rows:
        a = (r["src"], int(r["sport"]))
        b = (r["dst"], int(r["dport"]))
        endpoint_peers.setdefault(a, set()).add(b)
        endpoint_peers.setdefault(b, set()).add(a)

    client_ips, server_ips, server_ports = set(), set(), set()
    for r in flow_rows:
        a = (r["src"], int(r["sport"]))
        b = (r["dst"], int(r["dport"]))
        deg_a, deg_b = len(endpoint_peers[a]), len(endpoint_peers[b])
        if deg_a > deg_b and deg_a >= 2:
            server_ep, client_ep = a, b
        elif deg_b > deg_a and deg_b >= 2:
            server_ep, client_ep = b, a
        else:
            pa, pb = a[1], b[1]
            if pa == pb:
                return [], None, "Ambiguous client direction: no TCP SYN/SYN-ACK and identical TCP ports."
            low_ep, high_ep = (a, b) if pa < pb else (b, a)
            low_p, high_p = low_ep[1], high_ep[1]
            if (low_p < 1024 and high_p >= 1024) or (
                low_p <= 10000 and high_p >= 10000 and high_p >= 2 * low_p
            ):
                server_ep, client_ep = low_ep, high_ep
            else:
                return (
                    [],
                    None,
                    f"Ambiguous client direction: no TCP SYN/SYN-ACK and ports ({pa}, {pb}) do not separate service from ephemeral.",
                )
        client_ips.add(client_ep[0])
        server_ips.add(server_ep[0])
        server_ports.add(server_ep[1])

    if not client_ips or (client_ips & server_ips):
        return [], None, "Ambiguous client direction: endpoint IPs act as both client and server."

    cidrs = [f"{ip}/128" if ":" in ip else f"{ip}/32" for ip in sorted(client_ips)]
    first = flow_rows[0]
    ref = dict(
        capture_id=first["capture_id"],
        file=names[first["capture_id"]],
        frame=first["frame"],
        display_filter=f"frame.number == {first['frame']}",
    )
    return (
        cidrs,
        dict(
            kind="client_cidrs",
            method="server_port_heuristic",
            capture_ids=[first["capture_id"]],
            client_cidrs=cidrs,
            metrics=dict(
                method="server_port_heuristic",
                client_ips=sorted(client_ips),
                server_ips=sorted(server_ips),
                server_ports=sorted(server_ports),
                shared_flows=len(flow_rows),
            ),
            evidence=[ref],
            reason=f"Client CIDR(s) {', '.join(cidrs)} inferred from server-port heuristic (service port(s) {sorted(server_ports)}).",
        ),
        None,
    )


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


def _assemble_single_topology(
    db,
    base_model: Topology,
    captures: list[dict],
    raw_suggestions: dict,
    all_captures: list[dict] | None = None,
):
    ready_ids = [c["id"] for c in captures]
    ready_set = set(ready_ids)
    names = {c["id"]: c["name"] for c in captures}
    warnings = [
        s["warning"]
        for s in raw_suggestions.get("items", [])
        if s.get("warning") and set(s.get("capture_ids", ())) <= ready_set
    ]
    inferences = []

    if len(captures) < 2:
        return dict(
            status="ambiguous",
            ambiguous=True,
            confirmed=False,
            reason="At least two ready captures are required to assemble a path.",
            topology=base_model.model_dump(),
            inferences=[],
            warnings=warnings,
        )

    all_points_by_cid = _default_points(all_captures or captures, base_model.points)
    points_by_cid = {cid: all_points_by_cid[cid].model_copy(deep=True) for cid in ready_ids}

    client_cidrs, cidr_inference, cidr_err = _infer_client_cidrs(db, names, ready_ids)
    if cidr_err or not client_cidrs:
        excl_reason = _capture_exclusion_reason(db, captures, ready_ids)
        return dict(
            status="ambiguous",
            ambiguous=True,
            confirmed=False,
            reason=excl_reason or cidr_err or "Client direction could not be inferred unambiguously.",
            topology=base_model.model_dump(),
            inferences=[],
            warnings=warnings,
        )
    inferences.append(cidr_inference)
    base_model = base_model.model_copy(update=dict(client_cidrs=client_cidrs))
    client_ips = [cidr.split("/")[0] for cidr in client_cidrs]

    placeholders = ",".join("?" for _ in ready_ids)
    ip_placeholders = ",".join("?" for _ in client_ips)
    ttl_rows = rows(
        db,
        f"""WITH shared_flows AS (
            SELECT least(tuple_key, reverse_tuple) AS canon
            FROM packets
            WHERE capture_id IN ({placeholders}) AND proto='TCP' AND (unsupported IS NULL OR unsupported='')
            GROUP BY 1 HAVING count(DISTINCT capture_id) >= 2
        )
        SELECT p.capture_id,
               median(p.ttl) FILTER (WHERE p.src IN ({ip_placeholders})) AS fwd_ttl,
               median(p.ttl) FILTER (WHERE p.dst IN ({ip_placeholders})) AS rev_ttl,
               count(*) FILTER (WHERE p.src IN ({ip_placeholders})) AS fwd_n,
               count(*) FILTER (WHERE p.dst IN ({ip_placeholders})) AS rev_n,
               min(p.frame) FILTER (WHERE p.src IN ({ip_placeholders})) AS fwd_frame,
               min(p.frame) FILTER (WHERE p.dst IN ({ip_placeholders})) AS rev_frame,
               count(*) FILTER (WHERE p.length > 1500 AND p.ttl IN (64, 128) AND p.src IN ({ip_placeholders})) AS fwd_super,
               count(*) FILTER (WHERE p.length > 1500 AND p.ttl IN (64, 128) AND p.dst IN ({ip_placeholders})) AS rev_super
        FROM packets p
        JOIN shared_flows sf ON least(p.tuple_key, p.reverse_tuple) = sf.canon
        WHERE p.capture_id IN ({placeholders}) AND p.proto='TCP'
          AND (p.unsupported IS NULL OR p.unsupported='')
        GROUP BY p.capture_id""",
        [
            *ready_ids,
            *client_ips,
            *client_ips,
            *client_ips,
            *client_ips,
            *client_ips,
            *client_ips,
            *client_ips,
            *client_ips,
            *ready_ids,
        ],
    )
    ttl_by_cid = {r["capture_id"]: r for r in ttl_rows}
    missing_cid_ids = [
        cid
        for cid in ready_ids
        if cid not in ttl_by_cid
        or ((ttl_by_cid[cid]["fwd_n"] or 0) == 0 and (ttl_by_cid[cid]["rev_n"] or 0) == 0)
    ]
    if missing_cid_ids:
        excl_reason = _capture_exclusion_reason(db, captures, missing_cid_ids)
        missing_names = [names[cid] for cid in missing_cid_ids]
        return dict(
            status="ambiguous",
            ambiguous=True,
            confirmed=False,
            reason=excl_reason
            or f"Capture(s) {', '.join(missing_names)} share no directional TCP traffic with the rest of the folder.",
            topology=base_model.model_dump(),
            inferences=inferences,
            warnings=warnings,
        )

    dir_pairs = rows(
        db,
        f"""WITH unique_packets AS (
            SELECT capture_id, tuple_key, signature, ts, ttl, frame,
                   CASE WHEN src IN ({ip_placeholders}) THEN 'forward'
                        WHEN dst IN ({ip_placeholders}) THEN 'reverse'
                        ELSE 'unknown' END AS dir
            FROM packets
            WHERE capture_id IN ({placeholders}) AND proto='TCP' AND (unsupported IS NULL OR unsupported='')
            QUALIFY count(*) OVER (PARTITION BY capture_id, tuple_key, signature) = 1
        )
        SELECT a.capture_id AS a, b.capture_id AS b, a.dir,
               count(*) AS n,
               median((b.ts - a.ts) * 1e6) AS delta_us,
               quantile_cont((b.ts - a.ts) * 1e6, 0.95) - quantile_cont((b.ts - a.ts) * 1e6, 0.05) AS spread_us,
               median(a.ttl - b.ttl) AS ttl_step,
               arg_min(a.frame, abs((b.ts - a.ts) * 1e6)) AS frame_a,
               arg_min(b.frame, abs((b.ts - a.ts) * 1e6)) AS frame_b
        FROM unique_packets a
        JOIN unique_packets b USING (tuple_key, signature, dir)
        WHERE a.capture_id <> b.capture_id AND a.dir IN ('forward', 'reverse')
        GROUP BY a.capture_id, b.capture_id, a.dir""",
        [*client_ips, *client_ips, *ready_ids],
    )
    pair_stats = {(r["a"], r["b"], r["dir"]): r for r in dir_pairs}

    # 1a. Host captures
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
        return dict(
            status="ambiguous",
            ambiguous=True,
            confirmed=False,
            reason="Multiple host offload captures detected on the same endpoint side; assign host order manually.",
            topology=base_model.model_dump(),
            inferences=inferences,
            warnings=warnings,
        )

    # 1a. Stage pairs (disjoint)
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

    # 1a. Shared clock domains (connected components)
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

    # Build non-host units to order along the path
    units: list[list[str]] = list(stage_units)
    for cid in ready_ids:
        if cid not in host_cids and cid not in stage_used:
            pt = points_by_cid[cid]
            pt.stage_capture = False
            pt.side = "both"
            units.append([cid])

    def unit_fwd_profile(u: list[str]) -> tuple[float, float] | None:
        vals = [ttl_by_cid[c]["fwd_ttl"] for c in u if ttl_by_cid[c]["fwd_ttl"] is not None]
        return (float(vals[0]), float(vals[-1])) if vals else None

    def unit_rev_profile(u: list[str]) -> tuple[float, float] | None:
        vals = [ttl_by_cid[c]["rev_ttl"] for c in u if ttl_by_cid[c]["rev_ttl"] is not None]
        return (float(vals[-1]), float(vals[0])) if vals else None

    def compare_units(u1: list[str], u2: list[str]) -> tuple[int, str | None, list[dict], bool]:
        """Return (-1 if u1 before u2, +1 if u2 before u1, 0 if ambiguous, plus us_conflict flag)."""
        f1, f2 = unit_fwd_profile(u1), unit_fwd_profile(u2)
        r1, r2 = unit_rev_profile(u1), unit_rev_profile(u2)
        ttl_dir = 0
        if f1 is not None and f2 is not None:
            if f1[0] >= f2[0] and f1[1] >= f2[1] and (f1[0] > f2[0] or f1[1] > f2[1]):
                ttl_dir = -1
            elif f2[0] >= f1[0] and f2[1] >= f1[1] and (f2[0] > f1[0] or f2[1] > f1[1]):
                ttl_dir = 1
            elif f1 != f2:
                return (
                    0,
                    f"Ambiguous forward TTL profile between {[names[c] for c in u1]} ({f1}) and {[names[c] for c in u2]} ({f2}).",
                    [],
                    False,
                )
        if r1 is not None and r2 is not None:
            rev_dir = 0
            if r1[0] <= r2[0] and r1[1] <= r2[1] and (r1[0] < r2[0] or r1[1] < r2[1]):
                rev_dir = -1
            elif r2[0] <= r1[0] and r2[1] <= r1[1] and (r2[0] < r1[0] or r2[1] < r1[1]):
                rev_dir = 1
            elif r1 != r2:
                return (
                    0,
                    f"Ambiguous reverse TTL profile between {[names[c] for c in u1]} ({r1}) and {[names[c] for c in u2]} ({r2}).",
                    [],
                    False,
                )
            if ttl_dir and rev_dir and ttl_dir != rev_dir:
                return (
                    0,
                    f"Conflicting forward and reverse TTL order between {[names[c] for c in u1]} and {[names[c] for c in u2]}.",
                    [],
                    False,
                )
            ttl_dir = ttl_dir or rev_dir

        a_fwd, b_fwd = u1[-1], u2[0]
        a_rev, b_rev = u1[0], u2[-1]
        same_clock = clock_domain_of.get(a_fwd) is not None and clock_domain_of.get(
            a_fwd
        ) == clock_domain_of.get(b_fwd)
        fwd_stat = pair_stats.get((a_fwd, b_fwd, "forward"))
        rev_stat = pair_stats.get((a_rev, b_rev, "reverse"))
        f_us = fwd_stat["delta_us"] if fwd_stat and fwd_stat["n"] >= 2 else None
        r_us = rev_stat["delta_us"] if rev_stat and rev_stat["n"] >= 2 else None
        f_us_dir = (-1 if f_us > 0 else 1) if (f_us is not None and abs(f_us) >= 1.0) else 0
        r_us_dir = (-1 if r_us < 0 else 1) if (r_us is not None and abs(r_us) >= 1.0) else 0
        strict_ttl_sep = bool(
            (f1 is not None and f2 is not None and (f1[1] > f2[0] or f2[1] > f1[0]))
            or (r1 is not None and r2 is not None and (r1[1] < r2[0] or r2[1] < r1[0]))
        )
        refs = []
        stat_for_ref = fwd_stat or rev_stat
        if same_clock and stat_for_ref:
            refs = [
                dict(
                    capture_id=stat_for_ref["a"],
                    file=names[stat_for_ref["a"]],
                    frame=stat_for_ref["frame_a"],
                    display_filter=f"frame.number == {stat_for_ref['frame_a']}",
                ),
                dict(
                    capture_id=stat_for_ref["b"],
                    file=names[stat_for_ref["b"]],
                    frame=stat_for_ref["frame_b"],
                    display_filter=f"frame.number == {stat_for_ref['frame_b']}",
                ),
            ]

        us_conflict = False
        if ttl_dir:
            if strict_ttl_sep and (
                (f_us_dir and f_us_dir != ttl_dir) or (r_us_dir and r_us_dir != ttl_dir)
            ):
                us_conflict = True
            chosen = ttl_dir
        else:
            us_dir = 0
            if same_clock and (fwd_stat or rev_stat):
                if f_us_dir and r_us_dir and f_us_dir != r_us_dir:
                    return (
                        0,
                        f"Conflicting microsecond transit order between {[names[c] for c in u1]} and {[names[c] for c in u2]}.",
                        [],
                        False,
                    )
                us_dir = f_us_dir or r_us_dir
            if not us_dir:
                return (
                    0,
                    f"Ambiguous path order between {[names[c] for c in u1]} and {[names[c] for c in u2]}: equal TTLs and no shared-clock microsecond separation.",
                    [],
                    False,
                )
            chosen = us_dir

        if not refs:
            ca, cb = (a_fwd, b_fwd) if chosen < 0 else (u2[-1], u1[0])
            fa = ttl_by_cid[ca]["fwd_frame"] or ttl_by_cid[ca]["rev_frame"]
            fb = ttl_by_cid[cb]["fwd_frame"] or ttl_by_cid[cb]["rev_frame"]
            if fa and fb:
                refs = [
                    dict(capture_id=ca, file=names[ca], frame=fa, display_filter=f"frame.number == {fa}"),
                    dict(capture_id=cb, file=names[cb], frame=fb, display_filter=f"frame.number == {fb}"),
                ]
        return chosen, None, refs, us_conflict

    wins = {i: 0 for i in range(len(units))}
    hop_refs: dict[tuple[int, int], list[dict]] = {}
    conflicting_unit_pairs: list[tuple[int, int]] = []
    for i in range(len(units)):
        for j in range(i + 1, len(units)):
            cmp_val, err, refs, us_conflict = compare_units(units[i], units[j])
            if cmp_val == 0:
                return dict(
                    status="ambiguous",
                    ambiguous=True,
                    confirmed=False,
                    reason=err or "Path order between captures is ambiguous.",
                    topology=base_model.model_dump(),
                    inferences=inferences,
                    warnings=warnings,
                )
            if us_conflict:
                conflicting_unit_pairs.append((i, j))
            if cmp_val < 0:
                wins[i] += 1
                hop_refs[(i, j)] = refs
            else:
                wins[j] += 1
                hop_refs[(j, i)] = list(reversed(refs)) if refs else []

    if len(set(wins.values())) != len(units):
        return dict(
            status="ambiguous",
            ambiguous=True,
            confirmed=False,
            reason="Pairwise TTL/timestamp comparisons do not form a consistent linear path order.",
            topology=base_model.model_dump(),
            inferences=inferences,
            warnings=warnings,
        )

    ordered_indices = sorted(range(len(units)), key=lambda idx: -wins[idx])
    ordered_units = [units[idx] for idx in ordered_indices]

    if conflicting_unit_pairs:
        conflict_counts = {idx: 0 for idx in range(len(units))}
        for ia, ib in conflicting_unit_pairs:
            conflict_counts[ia] += 1
            conflict_counts[ib] += 1
        clean_shared = {idx: (1 if len(units[idx]) > 1 else 0) for idx in range(len(units))}
        for ia in range(len(units)):
            for ib in range(ia + 1, len(units)):
                if (ia, ib) not in conflicting_unit_pairs:
                    ca, cb = units[ia][-1], units[ib][0]
                    if clock_domain_of.get(ca) and clock_domain_of.get(ca) == clock_domain_of.get(cb):
                        clean_shared[ia] += 1
                        clean_shared[ib] += 1
        separate_unit_indices: set[int] = set()
        for ia, ib in conflicting_unit_pairs:
            key_a = (clean_shared[ia], -conflict_counts[ia], len(units[ia]), -wins[ia])
            key_b = (clean_shared[ib], -conflict_counts[ib], len(units[ib]), -wins[ib])
            separate_unit_indices.add(ia if key_a <= key_b else ib)
        separate_cids = {cid for u_idx in separate_unit_indices for cid in units[u_idx]}
        for u_idx in sorted(separate_unit_indices, key=lambda idx: -wins[idx]):
            for cid in units[u_idx]:
                clock_domain_of.pop(cid, None)
                points_by_cid[cid].clock_domain = None
                warn_msg = (
                    f"{names[cid]} timestamps are inconsistent with its TTL position; "
                    f"treated as a separate clock (offset fitted)"
                )
                if warn_msg not in warnings:
                    warnings.append(warn_msg)
        domain_members: dict[str, list[str]] = {}
        for cid, dom in list(clock_domain_of.items()):
            domain_members.setdefault(dom, []).append(cid)
        for dom, members in domain_members.items():
            if len(members) < 2:
                for cid in members:
                    clock_domain_of.pop(cid, None)
                    points_by_cid[cid].clock_domain = None
        inferences = [
            inf
            for inf in inferences
            if not (inf.get("kind") == "shared_clock" and set(inf.get("capture_ids", ())) & separate_cids)
        ]

    # Verify host capture TTL consistency against wire units
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

    # Check adjacent non-stage wire units for name/order mismatch warning when both TTL and µs order are present
    for idx_a, idx_b in zip(ordered_indices, ordered_indices[1:]):
        ua, ub = units[idx_a], units[idx_b]
        if len(ua) == 1 and len(ub) == 1:
            ca, cb = ua[0], ub[0]
            f_st = pair_stats.get((ca, cb, "forward"))
            r_st = pair_stats.get((ca, cb, "reverse"))
            if (
                f_st
                and r_st
                and f_st["ttl_step"] > 0
                and f_st["delta_us"] > 0
                and r_st["ttl_step"] < 0
                and r_st["delta_us"] < 0
            ):
                warn = _mismatch_warning(names[ca], names[cb])
                if warn and warn not in warnings:
                    warnings.append(warn)

    # Record path_order inference with concrete evidence
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
                g_res = _assemble_single_topology(
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

        res = _assemble_single_topology(db, base_model, captures, raw_suggestions, all_captures=captures)
        for w in warnings:
            if w not in res["warnings"]:
                res["warnings"].insert(0, w)
        return res


def assemble_and_analyze(project, base_topology=None, progress=None, cancel=None):
    from .analysis import analyze

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
