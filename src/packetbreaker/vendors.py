"""Vendor metadata adapters. All protocol fields are decoded by tshark."""

import json

CHECKPOINT_FIELDS = ["fw1.direction", "fw1.chain", "fw1.interface", "fw1.uuid"]
VENDOR_FIELDS = CHECKPOINT_FIELDS


def decoded_vendor(fields):
    decoded = {key: fields.get(key) for key in VENDOR_FIELDS if fields.get(key)}
    if not decoded:
        return None
    if decoded.get("fw1.direction"):
        direction, chain = decoded["fw1.direction"], decoded.get("fw1.chain", "")
        decoded["adapter"] = "checkpoint"
        decoded["stage"] = direction + chain if direction + chain in ("oe", "OE") else direction
    return json.dumps(decoded)


def point_selector(point):
    if point.vendor == "checkpoint":
        return " AND json_extract_string(vendor,'$.stage')=?", [point.vendor_stage]
    return "", []


def checkpoint_audit(db, topology):
    """Upgrade only complete, explicitly attested inspection paths; reuse packet identities."""
    from .store import rows
    from .evidence import evidence

    result = []
    used = set(topology.forward + topology.reverse)
    for point in topology.points:
        if point.vendor != "checkpoint" or point.vendor_stage != "i" or point.id not in used:
            continue
        downstream = [
            p
            for p in topology.points
            if p.vendor == "checkpoint"
            and p.device == point.device
            and p.capture_id == point.capture_id
            and p.id in used
            and p.vendor_stage != "i"
        ]
        stages = {p.vendor_stage for p in downstream}
        inv = json.loads(
            db.execute("SELECT inventory FROM captures WHERE id=?", [point.capture_id]).fetchone()[0]
        )
        complete = (
            point.inspection_complete
            and {"I", "o"} <= stages
            and not (
                inv.get("damaged_tail")
                or inv.get("zero_tail_bytes")
                or inv.get("timestamp_excluded_counts")
                or inv.get("ifdrop")
                or inv.get("osdrop")
            )
        )
        end = inv.get("end")
        missing = rows(
            db,
            """SELECT o.* FROM obs o WHERE point=? AND eligible AND NOT EXISTS(
            SELECT 1 FROM obs b WHERE b.packet_key=o.packet_key AND b.point IN (SELECT unnest(?::VARCHAR[])))""",
            [point.id, [p.id for p in downstream]],
        )
        for obs in missing:
            covered = complete and end is not None and obs["ts"] + topology.match_window_ms / 1000 <= end
            result.append(
                dict(
                    point=point.id,
                    device=point.device,
                    stage="i → no I/o",
                    flow=obs["flow"],
                    packet_key=obs["packet_key"],
                    frame=obs["frame"],
                    capture_id=point.capture_id,
                    time=obs["corrected"],
                    status="confirmed_device_drop" if covered else "unknown",
                    reason="Packet absent after pre-inbound inspection in a complete mapped stage capture"
                    if covered
                    else "Inspection coverage incomplete or not attested; cannot confirm a device drop",
                    evidence=evidence(db, "o.point=? AND o.frame=?", [point.id, obs["frame"]], 1),
                )
            )
    return result
