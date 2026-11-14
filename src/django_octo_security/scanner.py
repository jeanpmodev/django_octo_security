import importlib.metadata
import json
import ssl
import urllib.error
import urllib.request


OSV_API_HOST = "api.osv.dev"
OSV_BATCH_PATH = "/v1/querybatch"
OSV_VULN_PATH = "/v1/vulns/"


def _get_ssl_context():
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "django-octo-security/0.1.0",
}


def get_installed_packages() -> list[dict]:
    packages = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        version = dist.version
        if name and version:
            packages.append(
                {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
            )
    return packages


def fetch_vuln_full_details(vuln_id: str) -> dict:
    url = f"https://{OSV_API_HOST}{OSV_VULN_PATH}{vuln_id}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "django-octo-security/0.1.0",
        },
    )
    try:
        with urllib.request.urlopen(
            req, timeout=8, context=_get_ssl_context()
        ) as response:
            data = json.loads(response.read().decode("utf-8"))
            import_source = data.get("database_specific", {}).get("import_source", "")
            references = [
                ref.get("url") for ref in data.get("references", []) if ref.get("url")
            ]
            aliases = data.get("aliases", [])
            fixed_versions = []
            for affected in data.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
            return {
                "id": data.get("id", vuln_id),
                "aliases": aliases,
                "summary": data.get("summary") or "No summary available.",
                "import_source": import_source,
                "references": references[:5],
                "fixed_versions": list(set(fixed_versions)),
            }
    except Exception as exc:
        return {
            "id": vuln_id,
            "aliases": [],
            "summary": f"Failed to retrieve details: {exc}",
            "import_source": "",
            "references": [],
            "fixed_versions": [],
        }


def run_full_cve_audit() -> dict:
    packages = get_installed_packages()
    if not packages:
        return {
            "total_packages": 0,
            "vulnerabilities": [],
            "status": "CLEAN",
            "error": "",
        }

    batch_url = f"https://{OSV_API_HOST}{OSV_BATCH_PATH}"
    payload = json.dumps({"queries": packages}).encode("utf-8")
    req = urllib.request.Request(
        batch_url,
        data=payload,
        headers=DEFAULT_HEADERS,
        method="POST",
    )

    enriched_findings = []
    try:
        with urllib.request.urlopen(
            req, timeout=15, context=_get_ssl_context()
        ) as response:
            batch_data = json.loads(response.read().decode("utf-8"))
            results = batch_data.get("results", [])
            for pkg_info, res in zip(packages, results):
                for v in res.get("vulns", []):
                    vuln_id = v.get("id")
                    if vuln_id:
                        details = fetch_vuln_full_details(vuln_id)
                        details["package"] = pkg_info["package"]["name"]
                        details["installed_version"] = pkg_info["version"]
                        enriched_findings.append(details)

        return {
            "total_packages": len(packages),
            "vulnerabilities": enriched_findings,
            "status": "VULNERABLE" if enriched_findings else "CLEAN",
            "error": "",
        }
    except urllib.error.HTTPError as exc:
        return {
            "total_packages": len(packages),
            "vulnerabilities": [],
            "status": "ERROR",
            "error": f"OSV API HTTP {exc.code} ({exc.reason})",
        }
    except Exception as exc:
        return {
            "total_packages": len(packages),
            "vulnerabilities": [],
            "status": "ERROR",
            "error": str(exc),
        }
