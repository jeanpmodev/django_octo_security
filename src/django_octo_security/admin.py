from django.contrib import admin, messages
from django.http import HttpResponseRedirect
from django.urls import path, reverse
from django.utils.html import format_html, format_html_join
from .models import CveAuditScan
from .scanner import run_full_cve_audit


@admin.register(CveAuditScan)
class CveAuditScanAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "executed_at",
        "total_packages",
        "vulnerabilities_found",
        "status_badge",
    )
    readonly_fields = (
        "executed_at",
        "total_packages",
        "vulnerabilities_found",
        "status",
        "error_message",
        "rendered_report",
    )
    exclude = ("report_data",)
    actions = ["execute_cve_scan_action"]
    change_list_template = "admin/django_octo_security/cveauditscan/change_list.html"

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "run-scan/",
                self.admin_site.admin_view(self.run_scan_view),
                name="django_octo_security_run_scan",
            ),
        ]
        return custom_urls + urls

    def run_scan_view(self, request):
        result = run_full_cve_audit()
        scan = CveAuditScan.objects.create(
            total_packages=result["total_packages"],
            vulnerabilities_found=len(result["vulnerabilities"]),
            status=result["status"],
            error_message=result["error"],
            report_data=result["vulnerabilities"],
        )

        if scan.status == "ERROR":
            self.message_user(
                request,
                f"Audit #{scan.id} failed: {scan.error_message}",
                level=messages.ERROR,
            )
        else:
            msg = f"Audit #{scan.id} completed: {scan.total_packages} packages checked, {scan.vulnerabilities_found} vulnerabilities detected."
            self.message_user(
                request,
                msg,
                level=messages.WARNING
                if scan.vulnerabilities_found
                else messages.SUCCESS,
            )

        changelist_url = reverse("admin:django_octo_security_cveauditscan_changelist")
        return HttpResponseRedirect(changelist_url)

    @admin.display(description="Status")
    def status_badge(self, obj):
        palette = {
            "CLEAN": ("#065f46", "#d1fae5", "CLEAN"),
            "VULNERABLE": ("#991b1b", "#fee2e2", "VULNERABLE"),
            "ERROR": ("#92400e", "#fef3c7", "API ERROR"),
        }
        fg, bg, text = palette.get(obj.status, ("#374151", "#f3f4f6", obj.status))
        return format_html(
            '<span style="color:{}; background:{}; padding:4px 10px; border-radius:4px; font-weight:700; font-size:11px;">{}</span>',
            fg,
            bg,
            text,
        )

    @admin.display(description="Detailed CVE & Source Diagnostics")
    def rendered_report(self, obj):
        if obj.status == "ERROR":
            return format_html(
                '<p style="color:#b91c1c;"><strong>Query failure:</strong> {}</p>',
                obj.error_message,
            )
        if not obj.report_data:
            return format_html(
                '<p style="color:#059669;"><strong>Clean environment:</strong> No known vulnerabilities found across {} packages.</p>',
                obj.total_packages,
            )

        cards = []
        for item in obj.report_data:
            aliases = ", ".join(item.get("aliases", [])) or "No CVE alias"
            fixed = ", ".join(item.get("fixed_versions", [])) or "Check references"
            refs_html = format_html_join(
                "",
                '<li><a href="{}" target="_blank" rel="noopener">{}</a></li>',
                ((url, url) for url in item.get("references", [])),
            )
            cards.append(
                format_html(
                    '<div style="border:1px solid #e5e7eb; border-left:4px solid #dc2626; padding:12px; margin-bottom:12px; border-radius:4px; background:#fafafa;">'
                    '<h4 style="margin:0 0 6px 0; color:#111827;">{} (installed: <code>{}</code>) — <span style="color:#dc2626;">{}</span> <small>({})</small></h4>'
                    '<p style="margin:4px 0;"><strong>Summary:</strong> {}</p>'
                    '<p style="margin:4px 0;"><strong>Fixed Version:</strong> <code style="background:#dcfce7; color:#166534; padding:2px 6px;">{}</code></p>'
                    '<p style="margin:6px 0 2px 0;"><strong>Official References:</strong></p><ul style="margin:0; padding-left:18px;">{}</ul>'
                    "</div>",
                    item.get("package"),
                    item.get("installed_version"),
                    item.get("id"),
                    aliases,
                    item.get("summary"),
                    fixed,
                    refs_html,
                )
            )
        return format_html("{}", format_html_join("", "{}", ((c,) for c in cards)))

    @admin.action(description="Run new CVE environment audit")
    def execute_cve_scan_action(self, request, queryset):
        return self.run_scan_view(request)

    def has_add_permission(self, request):
        return False
