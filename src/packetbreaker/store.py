from contextlib import contextmanager
import json
from pathlib import Path
import threading

import duckdb
from . import __version__

PACKET_COLUMNS = {
    "capture_id": "VARCHAR",
    "frame": "BIGINT",
    "ts": "DOUBLE",
    "iface": "INTEGER",
    "src": "VARCHAR",
    "dst": "VARCHAR",
    "sport": "INTEGER",
    "dport": "INTEGER",
    "proto": "VARCHAR",
    "ipid": "BIGINT",
    "seq": "BIGINT",
    "ack": "BIGINT",
    "flags": "INTEGER",
    "length": "INTEGER",
    "wirelen": "INTEGER",
    "caplen": "INTEGER",
    "prefix": "VARCHAR",
    "payload_hash": "VARCHAR",
    "signature": "VARCHAR",
    "tuple_key": "VARCHAR",
    "reverse_tuple": "VARCHAR",
    "stream": "BIGINT",
    "ttl": "INTEGER",
    "dscp": "INTEGER",
    "mss": "INTEGER",
    "window": "BIGINT",
    "retrans": "BOOLEAN",
    "fast_retrans": "BOOLEAN",
    "spurious": "BOOLEAN",
    "out_of_order": "BOOLEAN",
    "acked_unseen": "BOOLEAN",
    "zero_window": "BOOLEAN",
    "rtt": "DOUBLE",
    "unsupported": "VARCHAR",
    "frame_hash": "VARCHAR",
    "icmp_id": "INTEGER",
    "icmp_seq": "INTEGER",
    "icmp_type": "INTEGER",
    "dns_id": "INTEGER",
    "dns_response": "BOOLEAN",
    "vendor": "VARCHAR",
}


class Project:
    def __init__(self, path: Path | str):
        self.path = Path(path).resolve()
        self.path.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS settings (key VARCHAR PRIMARY KEY, value VARCHAR)")
            db.execute("""CREATE TABLE IF NOT EXISTS captures (
                id VARCHAR PRIMARY KEY, path VARCHAR, name VARCHAR, identity VARCHAR,
                state VARCHAR, checkpoint BIGINT, inventory VARCHAR, error VARCHAR)""")
            cols = ",".join(f'"{k}" {v}' for k, v in PACKET_COLUMNS.items())
            db.execute(f"CREATE TABLE IF NOT EXISTS packets ({cols}, PRIMARY KEY(capture_id, frame))")
            db.execute(
                "UPDATE captures SET state='cancelled', error='Interrupted; resume available' WHERE state='ingesting'"
            )
            version = self.get(db, "schema_version")
            if version not in (None, 1, 2, 3, 4, 5):
                raise ValueError("Unsupported project schema version")
            if version in (1, 2):
                for column in ("frame_hash", "icmp_id", "icmp_seq", "icmp_type", "dns_id", "dns_response"):
                    db.execute(
                        f"ALTER TABLE packets ADD COLUMN IF NOT EXISTS {column} {PACKET_COLUMNS[column]}"
                    )
                db.execute(
                    "UPDATE captures SET state='stale',error='Phase 1.1 index upgrade: reattach to rebuild frame hashes'"
                )
                self.set(db, "report", None)
            db.execute(
                "CREATE TABLE IF NOT EXISTS excluded_frames(capture_id VARCHAR,frame BIGINT,reason VARCHAR,observed_ts DOUBLE,PRIMARY KEY(capture_id,frame))"
            )
            if version in (1, 2, 3):
                db.execute(
                    "UPDATE captures SET state='stale',error='Reattach once to validate capture timestamps'"
                )
                self.set(db, "report", None)
            legacy_offload = db.execute("""UPDATE captures SET state='stale',checkpoint=0,
                error='Reattach legacy offload captures to validate segmentation/fragment metadata'
                WHERE id IN (SELECT capture_id FROM packets WHERE proto='TCP' AND length>9000
                    AND unsupported LIKE 'Possible offload super-frame%') RETURNING id""").fetchall()
            if legacy_offload:
                self.set(db, "report", None)
            db.execute("ALTER TABLE packets ADD COLUMN IF NOT EXISTS vendor VARCHAR")
            self.set(db, "schema_version", 5)
            if self.get(db, "analysis_version") != __version__:
                self.set(db, "report", None)
                self.set(db, "analysis_version", __version__)

    @contextmanager
    def connect(self, allow_external=False):
        with self.lock:
            db = duckdb.connect(
                str(self.path / "project.duckdb"),
                config={
                    "memory_limit": "512MB",
                    "threads": "2",
                    "enable_external_access": str(allow_external).lower(),
                    "temp_directory": str(self.path / ".spill"),
                    "autoinstall_known_extensions": "false",
                    "autoload_known_extensions": "false",
                },
            )
            try:
                yield db
            finally:
                db.close()

    @staticmethod
    def get(db, key, default=None):
        row = db.execute("SELECT value FROM settings WHERE key=?", [key]).fetchone()
        return json.loads(row[0]) if row else default

    @staticmethod
    def set(db, key, value):
        db.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", [key, json.dumps(value)])

    def inventory(self):
        with self.connect() as db:
            data = rows(
                db, "SELECT id,path,name,state,checkpoint,inventory,error FROM captures ORDER BY name"
            )
            for capture in data:
                info = json.loads(capture["inventory"])
                if capture["state"] == "ready" and "observed_max_caplen" not in info:
                    stats = db.execute(
                        """SELECT max(caplen),min(caplen) FILTER(WHERE caplen<wirelen),
                        max(caplen) FILTER(WHERE caplen<wirelen) FROM packets WHERE capture_id=?""",
                        [capture["id"]],
                    ).fetchone()
                    info.update(
                        observed_max_caplen=stats[0],
                        truncated_caplen_min=stats[1],
                        truncated_caplen_max=stats[2],
                    )
                    db.execute(
                        "UPDATE captures SET inventory=? WHERE id=?", [json.dumps(info), capture["id"]]
                    )
                capture["inventory"] = info
            return data


def rows(db, sql, params=None):
    result = db.execute(sql, params or [])
    names = [c[0] for c in result.description]
    return [dict(zip(names, row)) for row in result.fetchall()]
