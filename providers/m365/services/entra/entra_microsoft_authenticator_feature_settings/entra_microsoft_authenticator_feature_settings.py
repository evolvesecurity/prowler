from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_microsoft_authenticator_feature_settings(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("(Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId microsoftAuthenticator | Select-Object -ExpandProperty AdditionalProperties).featureSettings | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                feature_settings = json.loads(result)
            except Exception as e:
                feature_settings = None
        else:
            feature_settings = result
        if not feature_settings or not isinstance(feature_settings, dict):
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"featureSettings": feature_settings},
                resource_name="featureSettings",
                resource_id="featureSettings",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No Microsoft Authenticator feature settings found."
            findings.append(report)
        else:
            fail_flag = False
            for setting_name, setting_value in feature_settings.items():
                state = setting_value.get('state', None) if isinstance(setting_value, dict) else None
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={"SettingName": setting_name, "State": state},
                    resource_name=setting_name,
                    resource_id=setting_name,
                    resource_location="global",
                )
                if state == "disabled":
                    report.status = "FAIL"
                    report.status_extended = f"{setting_name} is disabled."
                    fail_flag = True
                else:
                    report.status = "PASS"
                    report.status_extended = f"{setting_name} is enabled."
                findings.append(report)
        return findings
