from locust import HttpUser, between, task


class SecurityAuditUser(HttpUser):
    wait_time = between(1, 2)

    @task
    def load_security_audit_endpoint(self):
        self.client.get("/security-audit/")
