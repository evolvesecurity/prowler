from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_smtp_auth_disabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-TransportConfig | Select-Object -ExpandProperty SmtpClientAuthenticationDisabled | ConvertTo-Json")
        if isinstance(result, str):
            try:
                smtp_auth_disabled = json.loads(result)
            except Exception as e:
                smtp_auth_disabled = None
        else:
            smtp_auth_disabled = result
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"SmtpClientAuthenticationDisabled": smtp_auth_disabled},
            resource_name="SmtpClientAuthenticationDisabled",
            resource_id="SmtpClientAuthenticationDisabled",
            resource_location="global",
        )
        if smtp_auth_disabled is True:
            report.status = "PASS"
            report.status_extended = "SMTP Client Authentication is disabled (set to true)."
        else:
            report.status = "FAIL"
            report.status_extended = "SMTP Client Authentication is not disabled (set to false)."
        findings.append(report)
        return findings
