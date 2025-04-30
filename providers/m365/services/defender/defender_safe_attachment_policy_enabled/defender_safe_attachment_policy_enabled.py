from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
import json

class defender_safe_attachment_policy_enabled(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-SafeAttachmentPolicy | Select-Object Name,Enable | ConvertTo-Json")
        # Handle both str and list result
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
        if not policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Safe Attachment Policy",
                resource_id="SafeAttachmentPolicy",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Safe Attachment Policy data is unavailable. Ensure you have permission to run Get-SafeAttachmentPolicy."
            )
            findings.append(report)
            return findings
        any_enabled = False
        for policy in policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.get("Name", "Unknown"),
                resource_id=policy.get("Name", "Unknown"),
                resource_location="global",
            )
            if policy.get("Enable", False):
                report.status = "PASS"
                report.status_extended = (
                    f"Safe Attachment Policy '{policy.get('Name', 'Unknown')}' is enabled."
                )
                any_enabled = True
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Safe Attachment Policy '{policy.get('Name', 'Unknown')}' is NOT enabled."
                )
            findings.append(report)
        # If no policies are enabled, ensure at least one FAIL finding is present
        if not any_enabled and findings:
            # All findings will be FAIL, already appended
            pass
        return findings
