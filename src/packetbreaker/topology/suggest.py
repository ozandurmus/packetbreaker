"""Stage-pair, shared-clock, host-capture, and client-CIDR suggestion helpers."""

from pathlib import Path
import re

from ..store import rows

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


def _infer_cidrs_from_syn(db, names, ready_ids, placeholders):
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
    if not syn_rows:
        return None
    client_ips, server_ips = set(), set()
    for r in syn_rows:
        if (r["flags"] & 18) == 2:
            client_ips.add(r["src"])
            server_ips.add(r["dst"])
        else:
            client_ips.add(r["dst"])
            server_ips.add(r["src"])
    if not client_ips or (client_ips & server_ips):
        return None
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


def _infer_client_cidrs(db, names, ready_ids):
    placeholders = ",".join("?" for _ in ready_ids)
    syn_result = _infer_cidrs_from_syn(db, names, ready_ids, placeholders)
    if syn_result is not None:
        return syn_result

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
