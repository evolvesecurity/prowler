from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_sign_in_risk_policy(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                policies = json.loads(result)
            except Exception as e:
                policies = []
        else:
            policies = result if result else []
        if not policies:
            # No policies at all
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"Policies": []},
                resource_name="SignInRiskPolicies",
                resource_id="SignInRiskPolicies",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No Conditional Access policies found."
            findings.append(report)
        else:
            if isinstance(policies, dict):
                policies = [policies]
            for policy in policies:
                display_name = policy.get('DisplayName', 'Unknown')
                policy_id = policy.get('Id', 'Unknown')
                conditions = policy.get('Conditions', {})
                sign_in_risk_levels = conditions.get('SignInRiskLevels', [])
                has_sign_in_risk = bool(sign_in_risk_levels and any(level for level in sign_in_risk_levels if level))
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={"PolicyId": policy_id, "DisplayName": display_name, "SignInRiskLevels": sign_in_risk_levels},
                    resource_name=display_name,
                    resource_id=policy_id,
                    resource_location="global",
                )
                if has_sign_in_risk:
                    report.status = "PASS"
                    report.status_extended = f"Policy '{display_name}' has Sign-In Risk Levels configured: {sign_in_risk_levels}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Policy '{display_name}' does NOT have Sign-In Risk Levels configured."
                findings.append(report)
        return findings
