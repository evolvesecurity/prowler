from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_conditional_access_mfa_policy_check(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        # Get enabled Conditional Access policies with 'MFA' in their name
        result = provider.session.execute("Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -match 'MFA' -and $_.State -eq 'enabled' } | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                policies = json.loads(result)
            except Exception as e:
                policies = []
        else:
            policies = result if result else []
        if not policies:
            # No policies found
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"Policies": []},
                resource_name="ConditionalAccessPolicies",
                resource_id="ConditionalAccessPolicies",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No enabled Conditional Access policies contain 'MFA' in their name."
            findings.append(report)
        else:
            if isinstance(policies, dict):
                policies = [policies]
            for policy in policies:
                display_name = policy.get('DisplayName', 'Unknown')
                policy_id = policy.get('Id', 'Unknown')
                conditions = policy.get('Conditions', {})
                users = conditions.get('Users', {})
                include_users = users.get('IncludeUsers', [])
                exclude_users = users.get('ExcludeUsers', [])
                exclude_groups = users.get('ExcludeGroups', [])
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={
                        "PolicyId": policy_id,
                        "DisplayName": display_name,
                        "IncludeUsers": include_users,
                        "ExcludeUsers": exclude_users,
                        "ExcludeGroups": exclude_groups
                    },
                    resource_name=display_name,
                    resource_id=policy_id,
                    resource_location="global",
                )
                if include_users == "All" and not exclude_users and not exclude_groups:
                    report.status = "PASS"
                    report.status_extended = f"MFA Conditional Access Policy '{display_name}' applies to all users with no exclusions."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"MFA Conditional Access Policy '{display_name}' has exclusions."
                findings.append(report)
        return findings
