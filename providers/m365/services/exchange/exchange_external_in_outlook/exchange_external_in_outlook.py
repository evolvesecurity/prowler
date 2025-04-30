from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_external_in_outlook(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-ExternalInOutlook | ConvertTo-Json -Depth 10")
        if isinstance(result, dict):
            value = result.get("output", "")
        elif isinstance(result, list):
            value = result[0] if result else ""
        elif isinstance(result, str):
            value = result
        else:
            value = ""
        if isinstance(value, str):
            try:
                outlook_settings = json.loads(value)
            except Exception as e:
                outlook_settings = {}
        else:
            outlook_settings = value if value else {}
        enabled = outlook_settings.get('Enabled', None) if isinstance(outlook_settings, dict) else None
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"Enabled": enabled},
            resource_name="ExternalInOutlook",
            resource_id="ExternalInOutlook",
            resource_location="global",
        )
        if enabled is True:
            report.status = "PASS"
            report.status_extended = "'External in Outlook' is Enabled."
        elif enabled is False:
            report.status = "FAIL"
            report.status_extended = "'External in Outlook' is Disabled."
        else:
            report.status = "MANUAL"
            report.status_extended = "'External in Outlook' is not configured correctly."
        findings.append(report)
        return findings
