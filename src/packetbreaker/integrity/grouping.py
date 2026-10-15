"""Downstream packet finding grouping under upstream capture-miss findings."""


def group_downstream_findings(findings, topology):
    points = {p.id: p for p in topology.points}
    paths = {
        "forward": topology.forward,
        "reverse": topology.reverse or list(reversed(topology.forward)),
    }

    def seg_index(hop, direction):
        parts = hop.split(":")
        if len(parts) != 3:
            return None
        path = paths.get(direction, [])
        return path.index(parts[1]) if parts[1] in path else None

    captures_by_dir = {}
    for f in findings:
        if f["type"] == "capture_miss":
            idx = seg_index(f["hop"], f["direction"])
            if idx is not None:
                captures_by_dir.setdefault(f["direction"], []).append((idx, f))

    grouped_by_miss = {}
    kept = []
    for f in findings:
        if f["type"] != "downstream_packet":
            kept.append(f)
            continue
        idx = seg_index(f["hop"], f["direction"])
        candidates = [
            (m_idx, m_f)
            for m_idx, m_f in captures_by_dir.get(f["direction"], [])
            if idx is not None and m_idx <= idx and f["time_range"][0] + 0.005 >= m_f["time_range"][0]
        ]
        if not candidates:
            kept.append(f)
            continue
        _, target_miss = max(candidates, key=lambda item: (item[0], item[1]["time_range"][0]))
        grouped_by_miss.setdefault(target_miss["id"], (target_miss, []))[1].append(f)

    for target_miss, downstreams in grouped_by_miss.values():
        count = sum(df["metrics"].get("count", 1) for df in downstreams)
        labels = []
        for df in downstreams:
            parts = df["hop"].split(":")
            label = points[parts[2]].label if len(parts) == 3 and parts[2] in points else df["hop"]
            if label not in labels:
                labels.append(label)
        line = (
            f"{count} downstream-only packet observation(s) at {', '.join(labels)} "
            f"follow this capture miss (origin unknown; consistent with upstream capture miss)."
        )
        target_miss["downstream_summary"] = line
        target_miss["downstream_count"] = count
        target_miss["metrics"]["downstream_packet_count"] = count
        target_miss["summary"] = f"{target_miss['summary']} {line}"
        if "headline" in target_miss:
            target_miss["headline"] = f"{target_miss['headline']} {line}"
        seen_refs = {(r.get("point"), r.get("frame")) for r in target_miss["evidence"]}
        for df in downstreams:
            for r in df["evidence"]:
                key = (r.get("point"), r.get("frame"))
                if key not in seen_refs and len(target_miss["evidence"]) < 16:
                    seen_refs.add(key)
                    target_miss["evidence"].append(r)

    findings[:] = _merge_quality_limited(kept)


def _merge_quality_limited(findings):
    """One line per hop and quality reason for downstream-only packets that coverage, clock or
    capture quality already explains (e.g. capture edges); true candidates stay individual."""
    merged, kept = {}, []
    for f in findings:
        why = (f.get("metrics") or {}).get("quality_reason")
        if f["type"] != "downstream_packet" or not why:
            kept.append(f)
            continue
        key = (f["direction"], f["hop"], why)
        if key not in merged:
            carrier = dict(f, evidence=list(f["evidence"]), metrics=dict(f["metrics"], count=0))
            carrier["id"] = f"{f['id']}:merged"
            carrier["severity"] = "quality"
            merged[key] = carrier
            kept.append(carrier)
        carrier = merged[key]
        carrier["metrics"]["count"] += f["metrics"].get("count", 1)
        carrier["time_range"] = [
            min(carrier["time_range"][0], f["time_range"][0]),
            max(carrier["time_range"][1], f["time_range"][1]),
        ]
        for ref in f["evidence"]:
            if ref not in carrier["evidence"] and len(carrier["evidence"]) < 16:
                carrier["evidence"].append(ref)
    for carrier in merged.values():
        count = carrier["metrics"]["count"]
        text = (
            f"{count} downstream-only packet observation(s) explained by capture limits "
            f"({carrier['metrics']['quality_reason']}); not evidence of injection."
        )
        carrier["summary"] = carrier["headline"] = text
    return kept
