"""Payload modification linking, payload change detection, and downstream-only packet checks."""

from ..store import rows
from .common import LIMIT, metadata


def link_modified_payloads(db, topology, models):
    """Index unique header-matched payload changes once for matching and findings."""
    points = {p.id: p for p in topology.points}
    edges = [
        (a, b, direction)
        for direction, path in (
            ("forward", topology.forward),
            ("reverse", topology.reverse or topology.forward[::-1]),
        )
        for a, b in zip(path, path[1:])
        if "full_proxy" not in (points[a].translation, points[b].translation)
    ]
    db.execute(
        "CREATE OR REPLACE TEMP TABLE modified_payload_pairs(point_a VARCHAR,point_b VARCHAR,direction VARCHAR,frame_a BIGINT,frame_b BIGINT)"
    )
    db.execute("""CREATE OR REPLACE TEMP TABLE modified_headers AS SELECT point,canon,seq,ack,flags,length,direction,frame,corrected,
        json_extract_string(path_fields,'$.payload_complete') AS complete,json_extract_string(path_fields,'$.payload_sha256') AS digest
        FROM obs WHERE proto='TCP' AND length>0 AND eligible AND translation_reason IS NULL""")
    # Narrow rows, one edge at a time; keep uniqueness before filtering changed hashes.
    for point_a, point_b, direction in edges:
        db.execute(
            """INSERT INTO modified_payload_pairs WITH pairs AS (
            SELECT a.frame AS frame_a,b.frame AS frame_b,a.complete AS complete_a,b.complete AS complete_b,
                a.digest AS digest_a,b.digest AS digest_b
            FROM (SELECT * FROM modified_headers WHERE point=? AND direction=?) a
            JOIN (SELECT * FROM modified_headers WHERE point=? AND direction=?) b
            ON a.canon=b.canon AND a.seq=b.seq AND a.ack=b.ack AND a.flags=b.flags AND a.length=b.length
            WHERE abs(a.corrected-b.corrected)<=?
            QUALIFY count(*) OVER(PARTITION BY a.frame)=1 AND count(*) OVER(PARTITION BY b.frame)=1)
            SELECT ?,?,?,frame_a,frame_b FROM pairs WHERE complete_a='true' AND complete_b='true' AND digest_a<>digest_b""",
            [
                point_a,
                direction,
                point_b,
                direction,
                topology.match_window_ms / 1000,
                point_a,
                point_b,
                direction,
            ],
        )
    db.execute("DROP TABLE modified_headers")
    changed = set(db.execute("SELECT DISTINCT point_a,point_b FROM modified_payload_pairs").fetchall())
    for a, b, _ in edges:
        if (a, b) not in changed or any(models[points[p].capture_id].uncertainty is None for p in (a, b)):
            continue
        # Read current keys at each edge so successive mutations remain one physical occurrence.
        db.execute(
            """UPDATE obs SET packet_key=paired.before_key FROM (
            SELECT a.packet_key AS before_key,b.packet_key AS after_key FROM modified_payload_pairs m
            JOIN obs a ON a.point=m.point_a AND a.frame=m.frame_a
            JOIN obs b ON b.point=m.point_b AND b.frame=m.frame_b WHERE m.point_a=? AND m.point_b=?) paired
            WHERE obs.packet_key=paired.after_key""",
            [a, b],
        )


class PayloadChecksMixin:
    def payload_changes(self):
        for segment in self.segments:
            a, b = self.points[segment["point_a"]], self.points[segment["point_b"]]
            if any(p.translation == "full_proxy" for p in (a, b)) or (
                a.device == b.device and any(p.payload_transform != "none" for p in (a, b))
            ):
                continue
            candidates = rows(
                self.db,
                """SELECT a AS before_packet,b AS after_packet FROM modified_payload_pairs m
                JOIN integrity_obs a ON a.point=m.point_a AND a.frame=m.frame_a
                JOIN integrity_obs b ON b.point=m.point_b AND b.frame=m.frame_b
                WHERE m.point_a=? AND m.point_b=? AND m.direction=? AND a.eligible AND b.eligible
                    AND a.translation_reason IS NULL AND b.translation_reason IS NULL
                ORDER BY a.corrected LIMIT ?""",
                [a.id, b.id, segment["direction"], LIMIT + 1],
            )
            if len(candidates) > LIMIT:
                self.notes.append(
                    f"{segment['id']}: payload comparison sample limited to {LIMIT} unique pairs"
                )
            for pair in candidates[:LIMIT]:
                before, after = pair["before_packet"], pair["after_packet"]
                x, y = metadata(before), metadata(after)
                if (
                    not x.get("payload_complete")
                    or not y.get("payload_complete")
                    or x.get("payload_sha256") == y.get("payload_sha256")
                ):
                    continue
                why = self.reason(segment, before["corrected"])
                self.add(
                    segment,
                    "payload_modified",
                    before,
                    f"Payload changed across {self.location(segment)}"
                    if not why
                    else f"Payload comparison unknown at {self.location(segment)}: {why}",
                    "Unique canonical tuple/SEQ/ACK/flags/length pair within the match window; complete payload hashes differ. Ambiguous retries and offload boundaries are excluded. A change does not establish malicious intent.",
                    dict(
                        before_sha256=x["payload_sha256"],
                        after_sha256=y["payload_sha256"],
                        quality_reason=why,
                    ),
                    not why,
                    [before, after],
                    severity="high",
                )

    def downstream_only(self):
        modified = {
            (e["point"], e["frame"])
            for f in self.findings
            if f["type"] == "payload_modified"
            for e in f["evidence"]
        }
        for segment in self.segments:
            path = (
                self.topology.forward
                if segment["direction"] == "forward"
                else (self.topology.reverse or self.topology.forward[::-1])
            )
            if segment["point_b"] not in path or segment.get("location") == "device_stage":
                continue
            if segment.get("reason"):
                continue
            upstream = path[: path.index(segment["point_b"])]
            for packet in self.candidates(segment, "b.eligible AND b.proto='TCP' AND b.length>0"):
                if (packet["point"], packet["frame"]) in modified:
                    continue
                if self.db.execute(
                    "SELECT count(*) FROM obs WHERE point IN (SELECT unnest(?::VARCHAR[])) AND packet_key=?",
                    [upstream, packet["packet_key"]],
                ).fetchone()[0]:
                    continue
                why = self.reason(segment, packet["corrected"])
                self.add(
                    segment,
                    "downstream_packet",
                    packet,
                    f"Downstream-only packet at {self.points[packet['point']].label}; origin unknown"
                    + (
                        f": {why}"
                        if why
                        else "; injection and capture miss cannot be separated by absence alone"
                    ),
                    "Packet observed downstream without a matching upstream occurrence in the configured path. Unreported capture loss, translation or alternate routing can explain it; this is not confirmed malicious injection.",
                    dict(quality_reason=why),
                    False,
                )
