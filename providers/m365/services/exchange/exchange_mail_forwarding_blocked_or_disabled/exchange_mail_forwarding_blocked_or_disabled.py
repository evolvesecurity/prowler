from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_mail_forwarding_blocked_or_disabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        rules_result = provider.session.execute("Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | Select-Object Name, RedirectMessageTo | ConvertTo-Json -Depth 10")
        if isinstance(rules_result, str):
            try:
                rules = json.loads(rules_result)
            except Exception as e:
                rules = []
        else:
            rules = rules_result if rules_result else []
        if not rules:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"TransportRules": []},
                resource_name="MailForwardingBlockedOrDisabled",
                resource_id="MailForwardingBlockedOrDisabled",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = "No transport rules with mail forwarding found."
            findings.append(report)
        else:
            if isinstance(rules, dict):
                rules = [rules]
            for rule in rules:
                name = rule.get('Name', 'Unknown')
                redirect_to = rule.get('RedirectMessageTo', None)
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={"Name": name, "RedirectMessageTo": redirect_to},
                    resource_name=name,
                    resource_id=name,
                    resource_location="global",
                )
                report.status = "FAIL"
                report.status_extended = f"Transport rule '{name}' has mail forwarding enabled to: {redirect_to}."
                findings.append(report)
        # Also check HostedOutboundSpamFilterPolicy AutoForwardingMode
        spam_policy_result = provider.session.execute("Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode | ConvertTo-Json -Depth 10")
        if isinstance(spam_policy_result, str):
            try:
                policies = json.loads(spam_policy_result)
            except Exception as e:
                policies = []
        else:
            policies = spam_policy_result if spam_policy_result else []
        if isinstance(policies, dict):
            policies = [policies]
        for policy in policies:
            name = policy.get('Name', 'Unknown')
            auto_forwarding_mode = policy.get('AutoForwardingMode', None)
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"Name": name, "AutoForwardingMode": auto_forwarding_mode},
                resource_name=name,
                resource_id=name,
                resource_location="global",
            )
            if auto_forwarding_mode and auto_forwarding_mode.lower() == 'off':
                report.status = "PASS"
                report.status_extended = f"AutoForwardingMode is OFF for policy '{name}'."
            else:
                report.status = "FAIL"
                report.status_extended = f"AutoForwardingMode is NOT OFF for policy '{name}' (value: {auto_forwarding_mode})."
            findings.append(report)
        return findings
