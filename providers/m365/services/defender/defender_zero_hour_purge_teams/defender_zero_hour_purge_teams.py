from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell

class defender_zero_hour_purge_teams(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-TeamsProtectionPolicy | Select-Object Name,ZapEnabled | ConvertTo-Json")
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
            zap_enabled = policy.get("ZapEnabled")
            if zap_enabled is True:
                status = "PASS"
                status_extended = f"Policy '{policy.get('Name', 'Unknown')}' has ZapEnabled set to true."
            else:
                status = "FAIL"
                status_extended = f"Policy '{policy.get('Name', 'Unknown')}' has ZapEnabled set to {zap_enabled}."
                is_pass = False
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.get("Name", "Unknown"),
                resource_id=policy.get("Name", "Unknown"),
                resource_location="global",
            )
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings
