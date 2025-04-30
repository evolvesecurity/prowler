from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_conditional_access_session_controls_check(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq 'enabled' } | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                policies = json.loads(result)
            except Exception as e:
                policies = []
        else:
            policies = result if result else []
        found_session_controls = False
        configured_policies = []
        if not policies:
            status = "FAIL"
            status_extended = "No enabled Conditional Access policies found."
        else:
            if isinstance(policies, dict):
                policies = [policies]
            for policy in policies:
                display_name = policy.get('DisplayName', '')
                session_controls = policy.get('SessionControls', {})
                # Check if any value in SessionControls is not None or is enabled
                is_configured = False
                if session_controls and isinstance(session_controls, dict):
                    for v in session_controls.values():
                        if isinstance(v, dict):
                            if v.get('IsEnabled') is True:
                                is_configured = True
                                break
                            # If any other key in the dict is not None
                            if any(val not in (None, [], {}, "") for val in v.values()):
                                is_configured = True
                                break
                        elif v not in (None, [], {}, ""):
                            is_configured = True
                            break
                if is_configured:
                    found_session_controls = True
                    configured_policies.append(display_name)
            if found_session_controls:
                status = "PASS"
                status_extended = f"At least one enabled Conditional Access policy has session controls configured: {configured_policies}."
            else:
                status = "FAIL"
                status_extended = "No enabled Conditional Access policies have session controls configured."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"Policies": policies, "ConfiguredPolicies": configured_policies},
            resource_name="ConditionalAccessPolicies",
            resource_id="ConditionalAccessPolicies",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
