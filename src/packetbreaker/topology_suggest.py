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


def assemble_topology(project, base_topology: Topology | dict | None = None):
    raw_suggestions = suggest_topology(project)
    warnings = list(raw_suggestions.get("warnings", []))
    inferences = []

    captures = [c for c in project.inventory() if c["state"] == "ready"]
    with project.connect() as db:
        if base_topology is None:
            saved = project.get(db, "topology")
            base_model = Topology.model_validate(saved) if saved else Topology()
        elif isinstance(base_topology, Topology):
            base_model = base_topology.model_copy(deep=True)
        else:
            base_model = Topology.model_validate(base_topology)

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

        names = {c["id"]: c["name"] for c in captures}
        ready_ids = [c["id"] for c in captures]
        points_by_cid = _default_points(captures, base_model.points)

        client_cidrs, cidr_inference, cidr_err = _infer_client_cidrs(db, names, ready_ids)
        if cidr_err or not client_cidrs:
            return dict(
                status="ambiguous",
                ambiguous=True,
                confirmed=False,
                reason=cidr_err or "Client direction could not be inferred unambiguously.",
                topology=base_model.model_dump(),
                inferences=[],
                warnings=warnings,
            )
        inferences.append(cidr_inference)
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
        missing_cids = [
            names[cid]
            for cid in ready_ids
            if cid not in ttl_by_cid
            or ((ttl_by_cid[cid]["fwd_n"] or 0) == 0 and (ttl_by_cid[cid]["rev_n"] or 0) == 0)
        ]
        if missing_cids:
            return dict(
                status="ambiguous",
                ambiguous=True,
                confirmed=False,
                reason=f"Capture(s) {', '.join(missing_cids)} share no directional TCP traffic with the rest of the folder.",
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

    def compare_units(u1: list[str], u2: list[str]) -> tuple[int, str | None, list[dict]]:
        """Return (-1 if u1 before u2, +1 if u2 before u1, 0 if ambiguous)."""
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
                )
            if ttl_dir and rev_dir and ttl_dir != rev_dir:
                return (
                    0,
                    f"Conflicting forward and reverse TTL order between {[names[c] for c in u1]} and {[names[c] for c in u2]}.",
                    [],
                )
            ttl_dir = ttl_dir or rev_dir

        a_fwd, b_fwd = u1[-1], u2[0]
        a_rev, b_rev = u1[0], u2[-1]
        same_clock = clock_domain_of.get(a_fwd) is not None and clock_domain_of.get(
            a_fwd
        ) == clock_domain_of.get(b_fwd)
        fwd_stat = pair_stats.get((a_fwd, b_fwd, "forward"))
        rev_stat = pair_stats.get((a_rev, b_rev, "reverse"))
        us_dir = 0
        refs = []
        if same_clock and (fwd_stat or rev_stat):
            f_us = fwd_stat["delta_us"] if fwd_stat and fwd_stat["n"] >= 2 else None
            r_us = rev_stat["delta_us"] if rev_stat and rev_stat["n"] >= 2 else None
            if f_us is not None and abs(f_us) >= 1.0:
                us_dir = -1 if f_us > 0 else 1
            if r_us is not None and abs(r_us) >= 1.0:
                r_order = -1 if r_us < 0 else 1
                if us_dir and us_dir != r_order:
                    return (
                        0,
                        f"Conflicting microsecond transit order between {[names[c] for c in u1]} and {[names[c] for c in u2]}.",
                        [],
                    )
                us_dir = us_dir or r_order
            stat_for_ref = fwd_stat or rev_stat
            if stat_for_ref:
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

        if ttl_dir and us_dir and ttl_dir != us_dir:
            return (
                0,
                f"TTL order and microsecond timestamp order disagree between {[names[c] for c in u1]} and {[names[c] for c in u2]}.",
                [],
            )

        chosen = ttl_dir or us_dir
        if not chosen:
            return (
                0,
                f"Ambiguous path order between {[names[c] for c in u1]} and {[names[c] for c in u2]}: equal TTLs and no shared-clock microsecond separation.",
                [],
            )
        if not refs:
            ca, cb = (a_fwd, b_fwd) if chosen < 0 else (u2[-1], u1[0])
            fa = ttl_by_cid[ca]["fwd_frame"] or ttl_by_cid[ca]["rev_frame"]
            fb = ttl_by_cid[cb]["fwd_frame"] or ttl_by_cid[cb]["rev_frame"]
            if fa and fb:
                refs = [
                    dict(capture_id=ca, file=names[ca], frame=fa, display_filter=f"frame.number == {fa}"),
                    dict(capture_id=cb, file=names[cb], frame=fb, display_filter=f"frame.number == {fb}"),
                ]
        return chosen, None, refs

    wins = {i: 0 for i in range(len(units))}
    hop_refs: dict[tuple[int, int], list[dict]] = {}
    for i in range(len(units)):
        for j in range(i + 1, len(units)):
            cmp_val, err, refs = compare_units(units[i], units[j])
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
    for cid, pt in points_by_cid.items():
        if cid not in forward_cids:
            ordered_points.append(pt)

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
    report = analyze(project, assembly["topology"], progress=progress, cancel=cancel)
    report["suggested_topology"] = assembly
    with project.connect() as db:
        project.set(db, "report", report)
        project.set(db, "suggested_topology", assembly)
    return dict(suggested_topology=assembly, report=report)


def confirm_suggested_topology(project):
    with project.connect() as db:
        suggested = project.get(db, "suggested_topology")
        if not suggested or suggested.get("ambiguous"):
            raise ValueError("No assembled suggested topology is pending confirmation")
        suggested = {**suggested, "confirmed": True}
        project.set(db, "suggested_topology", suggested)
        project.set(db, "unconfirmed_topology", None)
        report = project.get(db, "report")
        if report:
            report["suggested_topology"] = suggested
            project.set(db, "report", report)
        return suggested
