from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class defender_safelinks_policy_office_apps_enabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        # Import required module
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        # Connect using certificate-based auth (no popup)
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_cmd)
        # Run the PowerShell command to get all SafeLinks policies
        result = provider.session.execute("Get-SafeLinksPolicy | ConvertTo-Json")
        # Fix: handle both str and list result
        if isinstance(result, str):
            try:
                policies = json.loads(result)
                if isinstance(policies, dict):
                    policies = [policies]
            except Exception:
                policies = []
        elif isinstance(result, list):
            policies = result
        else:
            policies = []
        expected_settings = {
            "EnableSafeLinksForEmail": True,
            "EnableSafeLinksForTeams": True,
            "EnableSafeLinksForOffice": True,
            "TrackClicks": True,
            "AllowClickThrough": False,
            "ScanUrls": True,
            "EnableForInternalSenders": True,
            "DeliverMessageAfterScan": True,
            "DisableUrlRewrite": False,
        }
        if not policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="SafeLinks Policy",
                resource_id="SafeLinksPolicy",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "SafeLinks policy data is unavailable. Ensure you have permission to run Get-SafeLinksPolicy."
            )
            findings.append(report)
            return findings
        for policy in policies:
            all_settings_correct = True
            incorrect_settings = []
            for key, expected_value in expected_settings.items():
                actual_value = policy.get(key, None)
                if actual_value != expected_value:
                    all_settings_correct = False
                    incorrect_settings.append(f"{key}: {actual_value} (expected: {expected_value})")
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.get("Name", "Unknown"),
                resource_id=policy.get("Name", "Unknown"),
                resource_location="global",
            )
            if all_settings_correct:
                report.status = "PASS"
                report.status_extended = f"All SafeLinks for Office Apps settings are correct in policy: {policy.get('Name', 'Unknown')}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SafeLinks for Office Apps settings are NOT correct in policy: {policy.get('Name', 'Unknown')}. "
                    f"Incorrect settings: {', '.join(incorrect_settings)}"
                )
            findings.append(report)
        return findings
