from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_guest_user_access(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty GuestUserRoleId | ConvertTo-Json")
        if isinstance(result, str):
            guest_user_role_id = result.strip()
        else:
            guest_user_role_id = result
        most_restrictive_values = [
            "10dae51f-b6af-4016-8d66-8c2a99b929b3",
            "2af84b1e-32c8-42b7-82bc-daa82404023b"
        ]
        if guest_user_role_id in most_restrictive_values:
            status = "PASS"
            status_extended = "Guest User Role ID is set to a most restrictive value."
        else:
            status = "FAIL"
            status_extended = "Guest User Role ID is not set to a most restrictive value."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"GuestUserRoleId": guest_user_role_id},
            resource_name="GuestUserRoleId",
            resource_id="GuestUserRoleId",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
