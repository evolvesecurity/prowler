from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class defender_exchange_online_spam_policies(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_cmd)
        result = provider.session.execute(
            "Get-HostedOutboundSpamFilterPolicy | Select-Object Name,NotifyOutboundSpamRecipients,NotifyOutboundSpam | ConvertTo-Json"
        )
        # Handle both str and list result
        if isinstance(result, str):
            try:
                policies = json.loads(result)
                if isinstance(policies, dict):
                    policies = [policies]
            except Exception as e:
                policies = []
        elif isinstance(result, list):
            policies = result
        elif isinstance(result, dict):
            policies = [result]
        else:
            policies = []
        if not policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Hosted Outbound Spam Filter Policy",
                resource_id="HostedOutboundSpamFilterPolicy",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No Hosted Outbound Spam Filter Policies found. Ensure you have permission to run Get-HostedOutboundSpamFilterPolicy."
            )
            findings.append(report)
            return findings
        for policy in policies:
            notify_recipients = policy.get("NotifyOutboundSpamRecipients")
            notify_outbound_spam = policy.get("NotifyOutboundSpam")
            # Check if NotifyOutboundSpam is True and NotifyOutboundSpamRecipients is not null/empty
            meets_criteria = (
                notify_outbound_spam is True and
                notify_recipients is not None and
                (isinstance(notify_recipients, list) and len(notify_recipients) > 0 or isinstance(notify_recipients, str) and notify_recipients.strip() != "")
            )
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.get("Name", "Unknown"),
                resource_id=policy.get("Name", "Unknown"),
                resource_location="global",
            )
            if meets_criteria:
                report.status = "PASS"
                report.status_extended = (
                    f"Spam policy '{policy.get('Name', 'Unknown')}' notifies outbound spam recipients and is correctly configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Spam policy '{policy.get('Name', 'Unknown')}' does NOT notify outbound spam recipients or is not correctly configured."
                )
            findings.append(report)
        return findings
