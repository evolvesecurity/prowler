from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
import json

class defender_atp_policy_spo_teams_odb_enabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = (
            f"Connect-ExchangeOnline {exo_auth_args} "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-AtpPolicyForO365 | Select-Object Name,EnableATPForSPOTeamsODB,EnableSafeDocs,AllowSafeDocsOpen | ConvertTo-Json")
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
        else:
            policies = []
        if not policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="ATP Policy for O365",
                resource_id="AtpPolicyForO365",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "ATP Policy for O365 data is unavailable. Ensure you have permission to run Get-AtpPolicyForO365."
            )
            findings.append(report)
            return findings
        for policy in policies:
            meets_criteria = (
                policy.get("EnableATPForSPOTeamsODB", False) is True and
                policy.get("EnableSafeDocs", False) is True and
                policy.get("AllowSafeDocsOpen", True) is False
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
                    f"ATP Policy '{policy.get('Name', 'Unknown')}' is correctly configured for SharePoint, OneDrive, and Teams."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"ATP Policy '{policy.get('Name', 'Unknown')}' is NOT correctly configured for SharePoint, OneDrive, and Teams."
                )
            findings.append(report)
        return findings
