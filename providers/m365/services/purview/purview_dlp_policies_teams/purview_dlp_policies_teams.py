from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class purview_dlp_policies_teams(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-DlpCompliancePolicy | ConvertTo-Json")
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
                resource_name="DLP Policy for Teams",
                resource_id="DlpPolicyTeams",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "No DLP policies found."
            findings.append(report)
            return findings
        teams_policies = [p for p in policies if p.get("Workload")]
        if not teams_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="DLP Policy for Teams",
                resource_id="DlpPolicyTeams",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No DLP policies found for Teams workload."
            findings.append(report)
            return findings
        is_compliant = True
        for policy in teams_policies:
            mode = policy.get("Mode")
            teams_location = policy.get("TeamsLocation", [])
            compliant = (mode == "Enable" and (isinstance(teams_location, list) and "All" in teams_location))
            if compliant:
                status = "PASS"
                status_extended = f"DLP policy '{policy.get('Name', 'Unknown')}' for Teams workload is compliant."
            else:
                status = "FAIL"
                status_extended = f"DLP policy '{policy.get('Name', 'Unknown')}' for Teams workload is not compliant. Mode: {mode}, TeamsLocation: {teams_location}"
                is_compliant = False
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
