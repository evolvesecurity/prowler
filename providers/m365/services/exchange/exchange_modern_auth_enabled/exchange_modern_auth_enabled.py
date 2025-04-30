from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_modern_auth_enabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled | ConvertTo-Json")
        if isinstance(result, dict):
            value = result.get("output", "")
        elif isinstance(result, list):
            value = result[0] if result else ""
        elif isinstance(result, str):
            value = result
        else:
            value = ""
        org_config = {}
        if value:
            try:
                org_config = json.loads(value)
            except Exception as e:
                org_config = {}
        oauth2_enabled = org_config.get('OAuth2ClientProfileEnabled', None) if isinstance(org_config, dict) else None
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"OAuth2ClientProfileEnabled": oauth2_enabled},
            resource_name="OAuth2ClientProfileEnabled",
            resource_id="OAuth2ClientProfileEnabled",
            resource_location="global",
        )
        if oauth2_enabled is True:
            report.status = "PASS"
            report.status_extended = "Modern Authentication (OAuth2ClientProfileEnabled) is Enabled."
        elif oauth2_enabled is False:
            report.status = "FAIL"
            report.status_extended = "Modern Authentication (OAuth2ClientProfileEnabled) is Disabled."
        else:
            report.status = "MANUAL"
            report.status_extended = "Modern Authentication (OAuth2ClientProfileEnabled) is not configured."
        findings.append(report)
        return findings
