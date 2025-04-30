from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_mailtips_enabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled | ConvertTo-Json")
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
                mailtips = json.loads(value)
            except Exception as e:
                mailtips = {}
        else:
            mailtips = value if value else {}
        all_tips = mailtips.get('MailTipsAllTipsEnabled', None) if isinstance(mailtips, dict) else None
        external_tips = mailtips.get('MailTipsExternalRecipientsTipsEnabled', None) if isinstance(mailtips, dict) else None
        group_metrics = mailtips.get('MailTipsGroupMetricsEnabled', None) if isinstance(mailtips, dict) else None
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={
                "MailTipsAllTipsEnabled": all_tips,
                "MailTipsExternalRecipientsTipsEnabled": external_tips,
                "MailTipsGroupMetricsEnabled": group_metrics
            },
            resource_name="MailTipsEnabled",
            resource_id="MailTipsEnabled",
            resource_location="global",
        )
        if all([all_tips, external_tips, group_metrics]):
            report.status = "PASS"
            report.status_extended = "All required MailTips settings are enabled."
        elif any([all_tips, external_tips, group_metrics]):
            report.status = "FAIL"
            report.status_extended = "One or more required MailTips settings are not enabled."
        else:
            report.status = "MANUAL"
            report.status_extended = "Unable to determine MailTips settings."
        findings.append(report)
        return findings
