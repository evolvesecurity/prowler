from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_user_app_consent(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object -ExpandProperty PermissionGrantPoliciesAssigned | ConvertTo-Json")
        if isinstance(result, str):
            try:
                policies = json.loads(result)
                if isinstance(policies, str):
                    policies = [policies]
            except Exception as e:
                policies = []
        elif isinstance(result, list):
            policies = result
        elif isinstance(result, dict):
            policies = [result]
        else:
            policies = []
        if not policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="User App Consent",
                resource_id="UserAppConsent",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = "No permission grant policies assigned for user app consent."
            findings.append(report)
            return findings
        if "ManagePermissionGrantsForSelf.microsoft-user-default-low" in policies:
            status = "FAIL"
            status_extended = "ManagePermissionGrantsForSelf.microsoft-user-default-low is present."
        else:
            status = "PASS"
            status_extended = "ManagePermissionGrantsForSelf.microsoft-user-default-low is not present."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"PermissionGrantPoliciesAssigned": policies},
            resource_name="User App Consent",
            resource_id="UserAppConsent",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
