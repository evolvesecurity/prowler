from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_guest_user_invitations(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty AllowInvitesFrom | ConvertTo-Json")
        if isinstance(result, str):
            allow_invites_from = result.strip()
        else:
            allow_invites_from = result
        allowed_values = [
            "none",
            "adminsAndGuestInviters",
            "admins",
            "everyone"
        ]
        policy_index = allowed_values.index(allow_invites_from) if allow_invites_from in allowed_values else -1
        required_index = allowed_values.index("adminsAndGuestInviters")
        if policy_index >= 0 and policy_index <= required_index:
            status = "PASS"
            status_extended = "Guest User Invitations setting is sufficiently restrictive."
        else:
            status = "FAIL"
            status_extended = "Guest User Invitations setting is not restrictive enough."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"AllowInvitesFrom": allow_invites_from},
            resource_name="AllowInvitesFrom",
            resource_id="AllowInvitesFrom",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
