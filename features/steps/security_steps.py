import json
from io import BytesIO
from unittest.mock import patch
from behave import given, then, when
from django.test import Client
from django_octo_security.models import CveAuditScan
from django_octo_security.scanner import run_full_cve_audit


@given("the database has a clean CVE audit scan recorded")
def step_given_clean_scan(context):
    CveAuditScan.objects.all().delete()
    context.scan = CveAuditScan.objects.create(
        total_packages=54,
        vulnerabilities_found=0,
        status="CLEAN",
        report_data=[],
    )


@when('a client requests the "{url}" endpoint')
def step_when_request_endpoint(context, url):
    client = Client()
    context.response = client.get(url)


@then("the response status code should be {status_code:d}")
def step_then_status_code(context, status_code):
    assert context.response.status_code == status_code


@then('the security showcase page should display "{expected_text}"')
def step_then_page_contains(context, expected_text):
    assert expected_text.encode("utf-8") in context.response.content


@given(
    'the environment has a vulnerable package "{pkg_name}" at version "{pkg_version}"'
)
def step_given_vulnerable_package(context, pkg_name, pkg_version):
    context.mock_pkg = [
        {"package": {"name": pkg_name, "ecosystem": "PyPI"}, "version": pkg_version}
    ]


@when("the CVE environment audit scanner executes")
def step_when_scanner_executes(context):
    batch_payload = BytesIO(
        json.dumps({"results": [{"vulns": [{"id": "PYSEC-2026-001"}]}]}).encode("utf-8")
    )
    detail_payload = BytesIO(
        json.dumps(
            {
                "id": "PYSEC-2026-001",
                "aliases": ["CVE-2026-9999"],
                "summary": "Simulated vulnerability for BDD validation",
                "affected": [{"ranges": [{"events": [{"fixed": "6.1.2"}]}]}],
                "references": [{"url": "https://osv.dev"}],
            }
        ).encode("utf-8")
    )

    with patch(
        "django_octo_security.scanner.get_installed_packages",
        return_value=context.mock_pkg,
    ):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.side_effect = [
                batch_payload,
                detail_payload,
            ]
            context.audit_result = run_full_cve_audit()


@then('the audit status should be "{expected_status}"')
def step_then_audit_status(context, expected_status):
    assert context.audit_result["status"] == expected_status


@then('the audit report should contain "{vuln_id}"')
def step_then_audit_contains_vuln(context, vuln_id):
    found_ids = [v["id"] for v in context.audit_result["vulnerabilities"]]
    assert vuln_id in found_ids
