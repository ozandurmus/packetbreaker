"""One-to-one UDP transactions scoped to a point and reversed observed tuple."""

from .store import rows
from .udp_index import protocol_evidence as evidence, frame_evidence

NOTE = "Known transaction IDs come from tshark. Unknown protocols pair forward initiators with reversed-tuple packets in a bounded window, never nearest-time guesses. Timing is same-point; unanswered traffic is not proof of an endpoint or device cause."


def build_udp(db, topology, segments):
    timeout = topology.udp_timeout_ms / 1000
    db.execute("""CREATE OR REPLACE TABLE udp_protocol AS SELECT o.*,
        CASE WHEN d."ntp.flags.mode" IS NOT NULL THEN 'NTP' WHEN d."snmp.data" IS NOT NULL THEN 'SNMP'
        WHEN d."radius.code" IS NOT NULL THEN 'RADIUS' WHEN d."syslog.level" IS NOT NULL THEN 'SYSLOG' ELSE 'UNKNOWN' END AS protocol,
        CASE WHEN d."ntp.flags.mode"='3' THEN 'request' WHEN d."ntp.flags.mode"='4' THEN 'response' WHEN d."ntp.flags.mode"='5' THEN 'oneway'
        WHEN d."snmp.data" IN ('0','1','3','5','6') THEN 'request' WHEN d."snmp.data"='2' THEN 'response' WHEN d."snmp.data" IN ('4','7') THEN 'oneway'
        WHEN d."radius.code" IN ('1','4','40','43') THEN 'request' WHEN d."radius.code" IN ('2','3','5','11','41','42','44','45') THEN 'response'
        WHEN d."syslog.level" IS NOT NULL THEN 'oneway' WHEN d."frame.protocols" LIKE '%:ntp%' OR d."frame.protocols" LIKE '%:snmp%' OR d."frame.protocols" LIKE '%:radius%' THEN 'unsupported'
        WHEN o.direction='forward' THEN 'request' WHEN o.direction='reverse' THEN 'response' ELSE 'unsupported' END AS role,
        CASE WHEN d."ntp.flags.mode"='3' THEN d."ntp.xmt" WHEN d."ntp.flags.mode"='4' THEN d."ntp.org"
        WHEN d."snmp.data" IS NOT NULL AND d."snmp.request_id" IS NOT NULL THEN
            CASE WHEN d."snmp.version" IN ('0','1') AND d."snmp.community" IS NOT NULL THEN concat(d."snmp.version",':',md5(d."snmp.community"),':',d."snmp.request_id")
                WHEN d."snmp.version"='3' AND d."snmp.msgID" IS NOT NULL THEN concat('3:',d."snmp.msgID",':',d."snmp.request_id") END
            ELSE d."radius.id" END AS token,
        d."radius.code" AS radius_code,c.reason AS decode_reason,
        o.eligible AND o.caplen=o.wirelen AND c.reason IS NULL AS complete
        FROM obs o LEFT JOIN udp_decoded d USING(point,frame) LEFT JOIN udp_decode_cache c USING(point)
        WHERE o.proto='UDP' AND o.dns_id IS NULL AND NOT coalesce(d."frame.protocols" LIKE '%:sip%' OR d."frame.protocols" LIKE '%:rtp%',false)""")
    if not db.execute("SELECT 1 FROM udp_protocol LIMIT 1").fetchone():
        db.execute("DROP TABLE IF EXISTS udp_transactions")
        return dict(
            summary=[],
            items=[],
            total=0,
            timeout_ms=topology.udp_timeout_ms,
            note=NOTE,
            scope="Query initiations in selected window",
        )
    db.execute(
        """CREATE OR REPLACE TEMP TABLE udp_candidates AS WITH c AS(
        SELECT q.point,q.frame,r.frame AS response_frame,r.ts AS response_ts,r.packet_key AS response_key
        FROM udp_protocol q JOIN udp_protocol r ON q.point=r.point AND q.flow=r.flow AND q.tuple_key=r.reverse_tuple AND q.protocol=r.protocol
        WHERE q.role='request' AND r.role='response' AND q.complete AND r.complete AND r.ts>=q.ts AND r.ts<=q.ts+?
        AND (q.protocol='UNKNOWN' OR q.token IS NOT NULL AND q.token=r.token)
        AND (q.protocol<>'RADIUS' OR q.radius_code='1' AND r.radius_code IN ('2','3','11') OR q.radius_code='4' AND r.radius_code='5'
            OR q.radius_code='40' AND r.radius_code IN ('41','42') OR q.radius_code='43' AND r.radius_code IN ('44','45')))
        SELECT *,count(*) OVER(PARTITION BY point,response_frame) AS owners FROM c""",
        [timeout],
    )
    db.execute(
        """CREATE OR REPLACE TABLE udp_transactions AS WITH pairs AS(
        SELECT point,frame,count(*) AS candidates,bool_or(owners<>1) AS ambiguous,min(response_frame) AS response_frame,
            min(response_ts) AS response_ts,min(response_key) AS response_key FROM udp_candidates GROUP BY point,frame),
        merged AS(SELECT q.*,coalesce(p.candidates,0) AS candidates,coalesce(p.ambiguous,false) AS ambiguous,
            CASE WHEN p.candidates=1 AND NOT p.ambiguous THEN p.response_frame END AS response_frame,
            CASE WHEN p.candidates=1 AND NOT p.ambiguous THEN p.response_key END AS response_key,
            CASE WHEN p.candidates=1 AND NOT p.ambiguous THEN (p.response_ts-q.ts)*1000 END AS latency_ms,
            q.ts+?<=c.stop AS covered,
            EXISTS(SELECT 1 FROM udp_protocol r WHERE r.point=q.point AND r.tuple_key=q.reverse_tuple
                AND r.ts BETWEEN q.ts AND q.ts+? AND NOT r.complete) AS incomplete_response,
            coalesce(try_cast(json_extract_string(i.inventory,'$.ifdrop') AS BIGINT),0)>0
                OR coalesce(try_cast(json_extract_string(i.inventory,'$.osdrop') AS BIGINT),0)>0 AS capture_drops
            FROM udp_protocol q LEFT JOIN pairs p USING(point,frame) LEFT JOIN captures i ON i.id=q.capture_id
            LEFT JOIN(SELECT point,max(ts) AS stop FROM obs GROUP BY point)c USING(point) WHERE role IN ('request','oneway','unsupported') AND (? IS NULL OR q.corrected>=?) AND (? IS NULL OR q.corrected<=?))
        SELECT *,CASE WHEN role='oneway' THEN 'no_response_expected' WHEN NOT complete OR role='unsupported' OR ambiguous OR candidates>1 THEN 'unknown'
            WHEN response_frame IS NOT NULL THEN 'answered' WHEN incomplete_response OR capture_drops OR protocol<>'UNKNOWN' AND role='request' AND token IS NULL THEN 'unknown' WHEN covered THEN 'unanswered' ELSE 'unknown' END AS status
        FROM merged""",
        [timeout, timeout, topology.start, topology.start, topology.end, topology.end],
    )
    # Reuse only supported disappearance classifications; a downstream reappearance remains capture miss.
    db.execute("CREATE OR REPLACE TEMP TABLE udp_supported(hop VARCHAR)")
    supported = [(s["id"],) for s in segments if s.get("loss_percent") is not None]
    if supported:
        db.executemany("INSERT INTO udp_supported VALUES (?)", supported)
    db.execute("""CREATE OR REPLACE TEMP TABLE udp_stops AS SELECT packet_key,arg_min(direction||':'||point_a||':'||point_b,ts) AS hop
        FROM events WHERE kind IN ('unrecovered_loss','impactful_loss','recovered_loss','confirmed_device_drop')
        AND direction||':'||point_a||':'||point_b IN(SELECT hop FROM udp_supported) GROUP BY packet_key""")
    db.execute("""CREATE OR REPLACE TEMP TABLE udp_far AS SELECT q.point,q.frame,count(DISTINCT p.response_key) AS replies,min(p.response_key) AS response_key
        FROM udp_transactions q JOIN udp_transactions p ON q.packet_key=p.packet_key AND p.status='answered' GROUP BY q.point,q.frame""")
    db.execute("""CREATE OR REPLACE TABLE udp_transactions AS SELECT t.*,CASE WHEN t.status='unanswered' THEN coalesce(q.hop,CASE WHEN f.replies=1 THEN r.hop END) END AS hop,
        CASE WHEN t.status='unanswered' AND q.hop IS NULL AND f.replies=1 THEN f.response_key END AS lost_response_key
        FROM udp_transactions t LEFT JOIN udp_stops q ON q.packet_key=t.packet_key LEFT JOIN udp_far f USING(point,frame)
        LEFT JOIN udp_stops r ON r.packet_key=f.response_key""")
    summary = rows(
        db,
        """SELECT point,protocol,dst AS endpoint,count(*) AS requests,count(*) FILTER(WHERE status='answered') AS answered,
        count(*) FILTER(WHERE status='unanswered') AS unanswered,count(*) FILTER(WHERE status='unknown') AS unknown,
        count(*) FILTER(WHERE status='no_response_expected') AS no_response_expected,
        quantile_cont(latency_ms,.5) AS p50_ms,quantile_cont(latency_ms,.95) AS p95_ms,max(latency_ms) AS max_ms FROM udp_transactions GROUP BY ALL ORDER BY point,protocol,endpoint""",
    )
    items = rows(
        db,
        "SELECT point,frame,flow,protocol,role,token,status,latency_ms,hop,packet_key,response_frame,lost_response_key,candidates,ambiguous,complete,covered,decode_reason,incomplete_response,capture_drops FROM udp_transactions ORDER BY ts,point LIMIT 200",
    )
    refs_by_frame = frame_evidence(
        db, [(i["point"], f) for i in items for f in (i["frame"], i["response_frame"])]
    )
    for item in items:
        if item["status"] == "answered":
            item["reason"] = "Unique reversed-tuple and decoded identity response"
        elif item["status"] == "no_response_expected":
            item["reason"] = "Known one-way traffic; no reply is expected"
        elif item["status"] == "unanswered":
            item["reason"] = "No unique response before the covered deadline; endpoint/device cause unknown"
        else:
            item["reason"] = item["decode_reason"] or (
                "Capture drops or incomplete candidate response; absence cannot establish timeout"
                if item["incomplete_response"] or item["capture_drops"]
                else "Ambiguous ownership, unsupported identity, incomplete packet or insufficient deadline coverage"
            )
        item["tooltip"] = NOTE
        item["evidence"] = [
            refs_by_frame[(item["point"], f)]
            for f in (item["frame"], item["response_frame"])
            if (item["point"], f) in refs_by_frame
        ]
        if item["hop"]:
            item["evidence"] += evidence(
                db, "o.packet_key IN (?,?)", [item["packet_key"], item["lost_response_key"]], 16
            )
    return dict(
        summary=summary,
        items=items,
        total=db.execute("SELECT count(*) FROM udp_transactions").fetchone()[0],
        timeout_ms=topology.udp_timeout_ms,
        note=NOTE,
        scope="Query initiations in the selected window; replies may extend to the covered deadline; bounded examples, all transactions stored",
    )
