from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class defender_priority_account_protection(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-EmailTenantSettings | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                settings = json.loads(result)
            except Exception as e:
                settings = {}
        elif isinstance(result, dict):
            settings = result
        else:
            settings = {}
        if "EnablePriorityAccountProtection" not in settings:
            status = "FAIL"
            status_extended = "'EnablePriorityAccountProtection' not found in output."
        elif settings["EnablePriorityAccountProtection"] is True:
            status = "PASS"
            status_extended = "Priority Account Protection is enabled."
        else:
            status = "FAIL"
            status_extended = "Priority Account Protection is not enabled."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings,
            resource_name="EmailTenantSettings",
            resource_id="EmailTenantSettings",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
