"""Bounded native-table export. Minimal OOXML uses inline strings, never formulas."""

import csv
import io
import json
import zipfile
from xml.sax.saxutils import escape
from .store import rows

TABLES = {
    "per_second": "SELECT *,strftime(to_timestamp(start) AT TIME ZONE 'UTC','%Y-%m-%dT%H:%M:%S.%fZ') AS utc_time FROM cycle_series ORDER BY start,point,flow",
    "flow_port": "SELECT * FROM cycle_flow_ports ORDER BY max_ms DESC",
    "periods": "SELECT * FROM cycle_periods ORDER BY point,flow,period",
    "top_cycles": "SELECT p.*,'frame.number == '||p.request_last_frame||' || frame.number == '||p.response_frame AS display_filter FROM cycle_top_points p",
    "rx_tx_components": "SELECT * FROM cycle_pairs ORDER BY time,hop,flow",
    "capture_points": "SELECT DISTINCT o.point,o.capture_id,c.name AS file FROM obs o JOIN captures c ON c.id=o.capture_id ORDER BY point",
    "flow_filters": "SELECT * FROM flow_filters ORDER BY capture_id,flow",
    "match_miss": "SELECT * FROM adjacent_match_rates ORDER BY start,point_a,point_b",
}


def column_name(index):
    result = ""
    while index:
        index, r = divmod(index - 1, 26)
        result = chr(65 + r) + result
    return result


def export_tables(project, format):
    if format not in ("csv", "xlsx"):
        raise ValueError("Choose csv or xlsx")
    output = io.BytesIO()
    with project.connect() as db, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        if (
            not project.get(db, "report")
            or not db.execute(
                "SELECT count(*) FROM duckdb_tables() WHERE table_name='cycle_points'"
            ).fetchone()[0]
        ):
            raise ValueError("Run the cycle analysis before exporting engine tables")
        if format == "xlsx":
            archive.writestr(
                "[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                + "".join(
                    f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                    for i in range(1, len(TABLES) + 1)
                )
                + "</Types>",
            )
            archive.writestr(
                "_rels/.rels",
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            )
            archive.writestr(
                "xl/workbook.xml",
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                + "".join(
                    f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>' for i, name in enumerate(TABLES, 1)
                )
                + "</sheets></workbook>",
            )
            archive.writestr(
                "xl/_rels/workbook.xml.rels",
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                + "".join(
                    f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>'
                    for i in range(1, len(TABLES) + 1)
                )
                + "</Relationships>",
            )
        for index, (name, sql) in enumerate(TABLES.items(), 1):
            cursor = db.execute(sql)
            headers = [c[0] for c in cursor.description]
            with archive.open(
                name + ".csv" if format == "csv" else f"xl/worksheets/sheet{index}.xml", "w"
            ) as target:
                if format == "xlsx":
                    target.write(
                        b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
                    )
                row_index = 0

                def write_row(values):
                    nonlocal row_index
                    row_index += 1
                    if format == "csv":
                        buffer = io.StringIO()
                        writer = csv.writer(buffer)
                        writer.writerow(
                            [
                                ("'" + v if v.lstrip().startswith(("=", "+", "-", "@")) else v)
                                if isinstance(v, str)
                                else v
                                for v in values
                            ]
                        )
                        target.write(buffer.getvalue().encode("utf-8"))
                    else:
                        if row_index > 1048576:
                            raise ValueError("XLSX sheet exceeds Excel row limit; use CSV export")
                        cells = []
                        for c, v in enumerate(values, 1):
                            if v is None:
                                continue
                            address = f"{column_name(c)}{row_index}"
                            if isinstance(v, bool):
                                cells.append(f'<c r="{address}" t="b"><v>{int(v)}</v></c>')
                            elif isinstance(v, (int, float)):
                                cells.append(f'<c r="{address}"><v>{v}</v></c>')
                            else:
                                value = "".join(ch for ch in str(v) if ord(ch) >= 32 or ch in "\n\r\t")
                                cells.append(
                                    f'<c r="{address}" t="inlineStr"><is><t xml:space="preserve">{escape(value)}</t></is></c>'
                                )
                        target.write((f'<row r="{row_index}">' + "".join(cells) + "</row>").encode("utf-8"))

                write_row(headers)
                while batch := cursor.fetchmany(2048):
                    for values in batch:
                        write_row(values)
                if format == "xlsx":
                    target.write(b"</sheetData></worksheet>")
        if format == "csv":
            archive.writestr(
                "README.json",
                json.dumps(
                    dict(
                        note="Epoch timestamps; ms durations. Opaque data cycles are not application messages. Frame references map to the saved project; unknown values are empty.",
                        captures=rows(db, "SELECT id,name FROM captures"),
                    ),
                    indent=2,
                ),
            )
    return output.getvalue()
