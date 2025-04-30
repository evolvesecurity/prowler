from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_audit_bypass_enabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MailboxAuditBypassAssociation -ResultSize unlimited | ConvertTo-Json -Depth 10")
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
                mailboxes = json.loads(value)
            except Exception as e:
                mailboxes = []
        else:
            mailboxes = value if value else []
        if not mailboxes:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"Mailboxes": []},
                resource_name="AuditBypassEnabled",
                resource_id="AuditBypassEnabled",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = "No Audit Bypass Enabled entries found."
            findings.append(report)
        else:
            if isinstance(mailboxes, dict):
                mailboxes = [mailboxes]
            fail_found = False
            for mailbox in mailboxes:
                if isinstance(mailbox, dict):
                    name = mailbox.get('Name', 'Unknown')
                    audit_bypass_enabled = mailbox.get('AuditBypassEnabled', False)
                else:
                    name = str(mailbox)
                    audit_bypass_enabled = False
                if audit_bypass_enabled:
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource={"Name": name, "AuditBypassEnabled": audit_bypass_enabled},
                        resource_name=name,
                        resource_id=name,
                        resource_location="global",
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Audit Bypass Enabled entry found for {name}."
                    findings.append(report)
                    fail_found = True
            if not fail_found:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={"Mailboxes": mailboxes},
                    resource_name="AuditBypassEnabled",
                    resource_id="AuditBypassEnabled",
                    resource_location="global",
                )
                report.status = "PASS"
                report.status_extended = "No Audit Bypass Enabled entries found."
                findings.append(report)
        return findings
