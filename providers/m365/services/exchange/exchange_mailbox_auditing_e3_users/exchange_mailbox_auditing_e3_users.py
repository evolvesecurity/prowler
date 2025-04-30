from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_mailbox_auditing_e3_users(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-EXOMailbox -PropertySets Audit -ResultSize Unlimited | Select-Object UserPrincipalName, AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                mailboxes = json.loads(result)
            except Exception as e:
                mailboxes = []
        else:
            mailboxes = result if result else []
        if not mailboxes:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"Mailboxes": []},
                resource_name="MailboxAuditingE3Users",
                resource_id="MailboxAuditingE3Users",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No mailbox audit data found."
            findings.append(report)
        else:
            if isinstance(mailboxes, dict):
                mailboxes = [mailboxes]
            for mailbox in mailboxes:
                user_principal_name = mailbox.get('UserPrincipalName', 'Unknown')
                audit_enabled = mailbox.get('AuditEnabled', False)
                audit_admin = mailbox.get('AuditAdmin', None)
                audit_delegate = mailbox.get('AuditDelegate', None)
                audit_owner = mailbox.get('AuditOwner', None)
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={
                        "UserPrincipalName": user_principal_name,
                        "AuditEnabled": audit_enabled,
                        "AuditAdmin": audit_admin,
                        "AuditDelegate": audit_delegate,
                        "AuditOwner": audit_owner
                    },
                    resource_name=user_principal_name,
                    resource_id=user_principal_name,
                    resource_location="global",
                )
                if audit_enabled:
                    report.status = "PASS"
                    report.status_extended = f"Mailbox auditing is enabled for {user_principal_name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Mailbox auditing is NOT enabled for {user_principal_name}."
                findings.append(report)
        return findings
