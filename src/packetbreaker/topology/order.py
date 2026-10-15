"""TTL and microsecond unit ordering and separate-clock conflict isolation."""

from ..store import rows
from .suggest import _mismatch_warning


def query_ttl_and_pair_stats(db, ready_ids, client_ips):
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
    return ttl_by_cid, pair_stats


def _unit_fwd_profile(u: list[str], ttl_by_cid: dict) -> tuple[float, float] | None:
    vals = [ttl_by_cid[c]["fwd_ttl"] for c in u if ttl_by_cid[c]["fwd_ttl"] is not None]
    return (float(vals[0]), float(vals[-1])) if vals else None


def _unit_rev_profile(u: list[str], ttl_by_cid: dict) -> tuple[float, float] | None:
    vals = [ttl_by_cid[c]["rev_ttl"] for c in u if ttl_by_cid[c]["rev_ttl"] is not None]
    return (float(vals[-1]), float(vals[0])) if vals else None


def compare_units(
    u1: list[str],
    u2: list[str],
    ttl_by_cid: dict,
    clock_domain_of: dict[str, str],
    pair_stats: dict,
    names: dict[str, str],
) -> tuple[int, str | None, list[dict], bool]:
    """Return (-1 if u1 before u2, +1 if u2 before u1, 0 if ambiguous, plus us_conflict flag)."""
    f1, f2 = _unit_fwd_profile(u1, ttl_by_cid), _unit_fwd_profile(u2, ttl_by_cid)
    r1, r2 = _unit_rev_profile(u1, ttl_by_cid), _unit_rev_profile(u2, ttl_by_cid)
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


def isolate_conflicting_clocks(
    units: list[list[str]],
    conflicting_unit_pairs: list[tuple[int, int]],
    wins: dict[int, int],
    clock_domain_of: dict[str, str],
    points_by_cid: dict,
    names: dict[str, str],
    warnings: list[str],
    inferences: list[dict],
) -> list[dict]:
    if not conflicting_unit_pairs:
        return inferences
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
    return [
        inf
        for inf in inferences
        if not (inf.get("kind") == "shared_clock" and set(inf.get("capture_ids", ())) & separate_cids)
    ]


def check_adjacent_mismatch_warnings(ordered_indices, units, pair_stats, names, warnings):
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
