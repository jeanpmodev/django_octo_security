from django.db import models


class CveAuditScan(models.Model):
    executed_at = models.DateTimeField(auto_now_add=True, verbose_name="Executed At")
    total_packages = models.PositiveIntegerField(
        default=0, verbose_name="Packages Checked"
    )
    vulnerabilities_found = models.PositiveIntegerField(
        default=0, verbose_name="Vulnerabilities Found"
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ("CLEAN", "Clean"),
            ("VULNERABLE", "Vulnerable"),
            ("ERROR", "Network Error"),
        ],
        default="CLEAN",
        verbose_name="Status",
    )
    error_message = models.TextField(blank=True, default="", verbose_name="Error Log")
    report_data = models.JSONField(
        default=list, blank=True, verbose_name="Technical Report (JSON)"
    )

    class Meta:
        app_label = "django_octo_security"
        verbose_name = "CVE Checker"
        verbose_name_plural = "CVE Checker"
        ordering = ["-executed_at"]

    def __str__(self):
        return f"Audit #{self.id} — {self.get_status_display()} ({self.vulnerabilities_found} CVEs)"
