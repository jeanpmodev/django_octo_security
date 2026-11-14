from django.urls import path
from .views import security_audit_view

app_name = "django_octo_security"

urlpatterns = [
    path("security-audit/", security_audit_view, name="audit"),
]
