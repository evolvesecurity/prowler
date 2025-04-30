from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class defender_inbound_anti_spam_policies(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-HostedContentFilterPolicy | Select-Object Identity,AllowedSenderDomains | ConvertTo-Json")
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
        is_pass = True
        for policy in policies:
            allowed_domains = policy.get("AllowedSenderDomains")
            if allowed_domains is not None and isinstance(allowed_domains, list) and len(allowed_domains) > 0:
                status = "FAIL"
                status_extended = f"Policy '{policy.get('Identity', 'Unknown')}' has non-empty AllowedSenderDomains: {allowed_domains}"
                is_pass = False
            else:
                status = "PASS"
                status_extended = f"Policy '{policy.get('Identity', 'Unknown')}' has an empty AllowedSenderDomains."
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.get("Identity", "Unknown"),
                resource_id=policy.get("Identity", "Unknown"),
                resource_location="global",
            )
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings
