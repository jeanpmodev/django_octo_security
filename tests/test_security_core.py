import json
from io import BytesIO
from unittest.mock import patch
import pytest
from django.test import Client
from django_octo_security.scanner import run_full_cve_audit


@pytest.mark.django_db
def test_security_audit_endpoint_single_query(django_assert_num_queries):
    client = Client()
    with django_assert_num_queries(1):
        response = client.get("/security-audit/")
    assert response.status_code == 200
    assert b"Django-Octo Security Engine" in response.content


@pytest.mark.django_db
@patch("django_octo_security.scanner.get_installed_packages")
@patch("urllib.request.urlopen")
def test_cve_scanner_detects_vulnerability(mock_urlopen, mock_packages):
    mock_packages.return_value = [
        {"package": {"name": "django", "ecosystem": "PyPI"}, "version": "4.0.0"}
    ]

    batch_response = BytesIO(
        json.dumps({"results": [{"vulns": [{"id": "PYSEC-2026-001"}]}]}).encode("utf-8")
    )
    detail_response = BytesIO(
        json.dumps(
            {
                "id": "PYSEC-2026-001",
                "aliases": ["CVE-2026-9999"],
                "summary": "Simulated vulnerability",
                "affected": [{"ranges": [{"events": [{"fixed": "4.2.0"}]}]}],
                "references": [{"url": "https://osv.dev"}],
            }
        ).encode("utf-8")
    )

    mock_urlopen.return_value.__enter__.side_effect = [batch_response, detail_response]

    result = run_full_cve_audit()
    assert result["status"] == "VULNERABLE"
    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["id"] == "PYSEC-2026-001"
