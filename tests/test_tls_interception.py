"""TLS attribution: two proxy candidates, a router and a link, negative cases first."""

import pytest
from packetbreaker.clock import ClockModel


@pytest.mark.parametrize(
    "negative", ["capture_miss", "missing_point", "clock", "tls13", "mtls_only", "consistent"]
)
def test_tls_negative_first(proxy_capture, negative):
    from packetbreaker.tls_analysis import tls_checks

    project, topology, truth, report = proxy_capture
    with project.connect() as db:
        db.execute("BEGIN TRANSACTION")
        try:
            models = {
                k: ClockModel(**{n: v for n, v in m.items() if n != "drift_ppm"})
                for k, m in report["clocks"].items()
            }
            if negative in ("capture_miss", "missing_point"):
                db.execute("DELETE FROM app_protocol WHERE kind='tls_certificate'")
            if negative == "clock":
                # Without a verified request pair TLS chains on separate connections cannot be compared.
                db.execute("UPDATE proxy_pairs SET status='unknown'")
            found, notes = tls_checks(
                db, topology, report["segments"], models, report["window"]["start"], report["window"]["end"]
            )
            if negative in ("tls13", "mtls_only", "consistent"):
                sni = truth["tls"][negative]
                found = [f for f in found if f["metrics"]["sni"] == sni]
                assert not found
                assert any(
                    n["sni"] == sni
                    and n["status"] == ("unknown" if negative in ("tls13", "mtls_only") else "consistent")
                    for n in notes
                )
                if negative == "tls13":
                    assert any(
                        "TLS 1.3 certificates encrypted" in n["reason"] for n in notes if n["sni"] == sni
                    )
            elif negative == "clock":
                assert not any(f["device"] in ("Proxy A", "Proxy B") for f in found)
            else:
                assert not found and any(n["status"] == "unknown" for n in notes)
        finally:
            db.execute("ROLLBACK")


@pytest.mark.parametrize("location", ["Proxy A", "Proxy B", "Router", "link"])
def test_tls_names_exact_device_or_link_unknown(proxy_capture, location):
    _, _, truth, report = proxy_capture
    found = [
        f
        for f in report["findings"]
        if f["type"] == "tls_interception" and f["metrics"]["sni"] == truth["tls"][location]
    ]
    supported = [f for f in found if f["confidence"] == "supported"]
    if location == "link":
        assert not supported
        assert any(f["device"] is None and "link between" in f["summary"] for f in found)
    else:
        assert len(supported) == 1, found
        assert supported[0]["device"] == location
        assert supported[0]["summary"] == f"TLS intercepted by {location} (not declared)"
        assert all(e["content_filter"] for e in supported[0]["evidence"])
        assert all(
            c["subject"] and c["issuer"] and len(c["fingerprint"]) == 64
            for key in ("before_chain", "after_chain")
            for c in supported[0]["metrics"][key]
        )


@pytest.mark.parametrize("device", ["Proxy A", "Proxy B", "Router"])
def test_declared_inspection_is_quality_not_an_undeclared_interception(proxy_capture, device):
    from packetbreaker.tls_analysis import tls_checks

    project, topology, truth, report = proxy_capture
    declared = topology.model_copy(
        update={
            "points": [
                p.model_copy(update={"payload_transform": "ssl_inspection"}) if p.device == device else p
                for p in topology.points
            ]
        }
    )
    models = {
        k: ClockModel(**{n: v for n, v in m.items() if n != "drift_ppm"}) for k, m in report["clocks"].items()
    }
    with project.connect() as db:
        found, _ = tls_checks(
            db, declared, report["segments"], models, report["window"]["start"], report["window"]["end"]
        )
    selected = [f for f in found if f["metrics"]["sni"] == truth["tls"][device]]
    assert selected and all(
        f["device"] == device and f["severity"] == "quality" and "not declared" not in f["summary"]
        for f in selected
    )


def test_always_first_proxy_mutant_is_rejected(proxy_capture):
    _, _, truth, report = proxy_capture
    finding = next(
        f
        for f in report["findings"]
        if f["type"] == "tls_interception"
        and f["metrics"]["sni"] == truth["tls"]["Proxy B"]
        and f["confidence"] == "supported"
    )

    def attribution_contract(f):
        assert f["device"] == "Proxy B"

    attribution_contract(finding)
    with pytest.raises(AssertionError):
        attribution_contract({**finding, "device": "Proxy A"})


def test_proxy_tls_json_and_offline_html_include_evidence(proxy_capture):
    import re
    from packetbreaker.export import export_data, html_report, FindingsExport

    project, _, _, _ = proxy_capture
    data = export_data(project)
    assert FindingsExport.model_validate(data).schema_version == 4
    assert {"proxy_reset_originated", "proxy_reset_propagated", "tls_interception"} <= {
        f["type"] for f in data["findings"]
    }
    assert data["report"]["proxies"]["transactions"] and data["report"]["tls"]
    assert all(
        f["evidence_refs"] and f["tooltip"]
        for f in data["findings"]
        if f["type"] in ("tls_interception", "proxy_reset_originated", "proxy_reset_propagated")
    )
    html = html_report(data)
    assert "TLS interception evidence" in html and "Full-proxy requests" in html
    assert re.search(r"""(?:src|href)\s*=\s*["']https?://""", html, re.I) is None
    assert "tls_interception" in html and "content_filter" in html
