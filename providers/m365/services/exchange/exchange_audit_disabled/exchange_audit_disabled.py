from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_audit_disabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-OrganizationConfig | Select-Object AuditDisabled | ConvertTo-Json")
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
                org_config = json.loads(value)
            except Exception as e:
                org_config = {}
        else:
            org_config = value if value else {}
        audit_disabled = org_config.get('AuditDisabled', None)
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"AuditDisabled": audit_disabled},
            resource_name="AuditDisabled",
            resource_id="AuditDisabled",
            resource_location="global",
        )
        if audit_disabled is False:
            report.status = "PASS"
            report.status_extended = "Audit is not disabled (AuditDisabled = False)."
        elif audit_disabled is True:
            report.status = "FAIL"
            report.status_extended = "Audit is disabled (AuditDisabled = True)."
        else:
            report.status = "MANUAL"
            report.status_extended = "Unable to determine the AuditDisabled status."
        findings.append(report)
        return findings
