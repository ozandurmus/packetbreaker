from contextlib import contextmanager
import json
from pathlib import Path
import threading

import duckdb

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
            if version not in (None, 1, 2):
                raise ValueError("Unsupported project schema version")
            if version == 1:
                db.execute("ALTER TABLE packets ADD COLUMN IF NOT EXISTS frame_hash VARCHAR")
                db.execute(
                    "UPDATE captures SET state='stale',error='Phase 1.1 index upgrade: reattach to rebuild frame hashes'"
                )
                self.set(db, "report", None)
            self.set(db, "schema_version", 2)

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
            return [
                dict(
                    id=r[0],
                    path=r[1],
                    name=r[2],
                    state=r[3],
                    checkpoint=r[4],
                    inventory=json.loads(r[5]),
                    error=r[6],
                )
                for r in db.execute(
                    "SELECT id,path,name,state,checkpoint,inventory,error FROM captures ORDER BY name"
                ).fetchall()
            ]


def rows(db, sql, params=None):
    result = db.execute(sql, params or [])
    names = [c[0] for c in result.description]
    return [dict(zip(names, row)) for row in result.fetchall()]
