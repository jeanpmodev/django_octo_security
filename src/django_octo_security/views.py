from django.shortcuts import render
from .models import CveAuditScan


def security_audit_view(request):
    latest_scan = CveAuditScan.objects.first()
    context = {
        "latest_scan": latest_scan,
        "security_headers": {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        },
    }
    return render(request, "security_audit.html", context)
