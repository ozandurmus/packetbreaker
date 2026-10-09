"""Exact field equality across two synthetic benchmark indexes (normalize capture IDs)."""

import argparse
import json
from pathlib import Path
import duckdb
from packetbreaker.store import PACKET_COLUMNS


def compare(before, after, output):
    with duckdb.connect(config={"memory_limit": "512MB", "threads": "2"}) as db:
        for label, path in (("before_index", before), ("after_index", after)):
            literal = str(path.resolve() / "project.duckdb").replace("'", "''")
            db.execute(f"ATTACH '{literal}' AS {label} (READ_ONLY)")
        old = dict(db.execute("SELECT name,id FROM before_index.captures").fetchall())
        new = dict(db.execute("SELECT name,id FROM after_index.captures").fetchall())
        assert old.keys() == new.keys()
        cols = [k for k in PACKET_COLUMNS if k != "capture_id"]
        mismatch = " OR ".join(f"a.{c} IS DISTINCT FROM b.{c}" for c in cols)
        results = []
        for name in sorted(old):
            count, bad = db.execute(
                f"""SELECT count(*),count(*) FILTER(WHERE {mismatch}) FROM
                (SELECT * FROM before_index.packets WHERE capture_id=?) a FULL OUTER JOIN
                (SELECT * FROM after_index.packets WHERE capture_id=?) b USING(frame)""",
                [old[name], new[name]],
            ).fetchone()
            results.append(dict(file=name, rows=count, mismatched_rows=bad))
        result = dict(
            capture_ids_normalized_by_filename=True,
            compared_fields=cols,
            captures=results,
            rows=sum(r["rows"] for r in results),
            mismatched_rows=sum(r["mismatched_rows"] for r in results),
        )
        output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        assert result["mismatched_rows"] == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    compare(args.before, args.after, args.output)
