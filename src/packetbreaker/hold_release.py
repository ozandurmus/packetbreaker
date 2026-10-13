"""Clock-independent compression of observed retransmission-copy spacing."""

from .store import rows
from .evidence import evidence
from .rtp import media_finding


def hold_release(db, segments):
    db.execute("""CREATE OR REPLACE TEMP TABLE copy_trains AS WITH repeated AS (
        SELECT point,flow,direction,seq,length FROM obs WHERE proto='TCP' AND length>0 AND eligible
        GROUP BY ALL HAVING count(*) BETWEEN 3 AND 8)
        SELECT point,flow,direction,seq,length,
        list(ts ORDER BY ts,frame) AS times,list(frame ORDER BY ts,frame) AS frames,list(ipid ORDER BY ts,frame) AS ids,
        min(coalesce(corrected,ts)) AS first_time,max(ts)-min(ts) AS span
        FROM obs JOIN repeated USING(point,flow,direction,seq,length) WHERE proto='TCP' AND length>0 AND eligible
        GROUP BY ALL""")
    findings = []
    for s in segments:
        trains = rows(
            db,
            """SELECT a.flow,a.seq,a.first_time,a.times AS wire_times,b.times AS host_times,
            a.frames AS wire_frames,b.frames AS host_frames FROM copy_trains a JOIN copy_trains b USING(flow,direction,seq)
            WHERE a.point=? AND b.point=? AND a.direction=? AND len(a.times)=len(b.times) AND a.ids=b.ids
            AND a.span>=.3 AND b.span<=least(.02,a.span*.1) ORDER BY a.span DESC LIMIT 100""",
            [s["point_a"], s["point_b"], s["direction"]],
        )
        for r in trains:
            wire = [(b - a) * 1000 for a, b in zip(r["wire_times"], r["wire_times"][1:])]
            received = [(b - a) * 1000 for a, b in zip(r["host_times"], r["host_times"][1:])]
            if not 100 <= wire[0] <= 400 or not all(1.4 <= b / a <= 2.6 for a, b in zip(wire, wire[1:])):
                continue
            refs = evidence(
                db,
                "(o.point=? AND o.frame IN (SELECT unnest(?::BIGINT[]))) OR (o.point=? AND o.frame IN (SELECT unnest(?::BIGINT[])))",
                [s["point_a"], r["wire_frames"], s["point_b"], r["host_frames"]],
                16,
                _expand_ranges=False,
            )
            text = f"Hold-and-release signature between {s['label'].replace(' → ', ' and ')}: copy spacing {', '.join(f'{v:.1f}' for v in wire)} ms becomes {', '.join(f'{v:.1f}' for v in received)} ms."
            f = media_finding(
                db,
                "hold_release",
                s,
                r["first_time"],
                text,
                dict(flow=r["flow"], seq=r["seq"], wire_spacing_ms=wire, receive_spacing_ms=received),
                refs,
            )
            f["tooltip"] = (
                "Spacing uses each capture’s own clock. RTO-like copies arrive compressed at the next point. This is a hold/release signature, not proof of a driver/device cause; capture batching can mimic it."
            )
            findings.append(f)
    return findings
