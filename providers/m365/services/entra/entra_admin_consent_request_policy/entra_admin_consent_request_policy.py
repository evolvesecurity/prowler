from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_admin_consent_request_policy(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgPolicyAdminConsentRequestPolicy | Select-Object IsEnabled,NotifyReviewers,RemindersEnabled,RequestDurationInDays | ConvertTo-Json")
        if isinstance(result, str):
            try:
                policy = json.loads(result)
            except Exception as e:
                policy = {}
        elif isinstance(result, dict):
            policy = result
        else:
            policy = {}
        is_enabled = policy.get("IsEnabled")
        if is_enabled is True:
            status = "PASS"
            status_extended = "Admin Consent Request Policy is enabled."
        else:
            status = "FAIL"
            status_extended = "Admin Consent Request Policy is disabled."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=policy,
            resource_name="AdminConsentRequestPolicy",
            resource_id="AdminConsentRequestPolicy",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
