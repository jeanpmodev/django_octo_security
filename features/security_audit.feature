Feature: Django-Octo Security Runtime and CVE Audit
  As a system administrator
  I want to verify security headers and audit installed Python packages for CVEs
  So that the application maintains high security compliance without impacting runtime performance

  Scenario: Render security audit endpoint with single query
    Given the database has a clean CVE audit scan recorded
    When a client requests the "/security-audit/" endpoint
    Then the response status code should be 200
    And the security showcase page should display "CLEAN"

  Scenario: Detect vulnerabilities in installed packages via OSV scanner
    Given the environment has a vulnerable package "django" at version "6.1.0"
    When the CVE environment audit scanner executes
    Then the audit status should be "VULNERABLE"
    And the audit report should contain "PYSEC-2026-001"
