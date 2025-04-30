from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_all_users_mfa_capable(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter \"IsMfaCapable eq false and UserType eq 'Member'\" | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                users = json.loads(result)
            except Exception as e:
                users = []
        else:
            users = result if result else []
        if not users:
            # All users are MFA capable
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"Users": []},
                resource_name="AllUsersMfaCapable",
                resource_id="AllUsersMfaCapable",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = "All member users are MFA capable."
            findings.append(report)
        else:
            for user in users:
                user_principal_name = user.get('UserPrincipalName', 'Unknown')
                is_mfa_capable = user.get('IsMfaCapable', False)
                is_admin = user.get('IsAdmin', False)
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={
                        "UserPrincipalName": user_principal_name,
                        "IsMfaCapable": is_mfa_capable,
                        "IsAdmin": is_admin
                    },
                    resource_name=user_principal_name,
                    resource_id=user_principal_name,
                    resource_location="global",
                )
                report.status = "FAIL"
                report.status_extended = f"User '{user_principal_name}' is not MFA capable. IsAdmin: {is_admin}"
                findings.append(report)
        return findings
