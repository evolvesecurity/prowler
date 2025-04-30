from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_self_service_password_reset(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgPolicyAuthenticationMethodPolicy | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                policies = json.loads(result)
            except Exception as e:
                policies = []
        else:
            policies = result if result else []
        if not policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"Policies": []},
                resource_name="AuthenticationMethodPolicies",
                resource_id="AuthenticationMethodPolicies",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No Self-Service Password Reset policies found."
            findings.append(report)
        else:
            if isinstance(policies, dict):
                policies = [policies]
            for policy in policies:
                policy_id = policy.get('Id', 'Unknown')
                display_name = policy.get('DisplayName', 'Unknown')
                is_enabled = policy.get('IsSelfServicePasswordResetEnabled', None)
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={
                        "PolicyId": policy_id,
                        "DisplayName": display_name,
                        "IsSelfServicePasswordResetEnabled": is_enabled
                    },
                    resource_name=display_name,
                    resource_id=policy_id,
                    resource_location="global",
                )
                if is_enabled is True:
                    report.status = "PASS"
                    report.status_extended = f"Self-Service Password Reset is enabled for policy '{display_name}'."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Self-Service Password Reset is NOT enabled for policy '{display_name}'."
                findings.append(report)
        return findings
