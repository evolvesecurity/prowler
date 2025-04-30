from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_third_party_application(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object AllowedToCreateApps | ConvertTo-Json")
        if isinstance(result, str):
            try:
                permissions = json.loads(result)
            except Exception as e:
                permissions = {}
        elif isinstance(result, dict):
            permissions = result
        else:
            permissions = {}
        allowed_to_create_apps = permissions.get("AllowedToCreateApps")
        if allowed_to_create_apps is False:
            status = "PASS"
            status_extended = "Third party application creation is not allowed."
        elif allowed_to_create_apps is True:
            status = "FAIL"
            status_extended = "Third party application creation is allowed."
        else:
            status = "FAIL"
            status_extended = "Unable to determine third party application creation setting."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=permissions,
            resource_name="DefaultUserRolePermissions",
            resource_id="DefaultUserRolePermissions",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
