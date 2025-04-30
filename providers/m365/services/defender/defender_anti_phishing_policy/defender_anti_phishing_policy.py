from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
import json

class defender_anti_phishing_policy(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        # Avoid duplicate -AppId and -Organization if already in exo_auth_args
        if "-AppId" in exo_auth_args or "-Organization" in exo_auth_args:
            connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        else:
            connect_cmd = (
                f"Connect-ExchangeOnline {exo_auth_args} "
                f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
            )
        provider.session.execute(connect_cmd)
        result = provider.session.execute(
            "Get-AntiPhishPolicy | Select-Object * | ConvertTo-Json"
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
                resource_name="Anti-Phishing Policy",
                resource_id="AntiPhishPolicy",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No Anti-Phishing Policies found. Ensure you have permission to run Get-AntiPhishPolicy."
            )
            findings.append(report)
            return findings
        expected_values = {
            "Enabled": True,
            "PhishThresholdLevel": 3,
            "EnableTargetedUserProtection": True,
            "EnableOrganizationDomainsProtection": True,
            "EnableMailboxIntelligence": True,
            "EnableMailboxIntelligenceProtection": True,
            "EnableSpoofIntelligence": True,
            "TargetedUserProtectionAction": "Quarantine",
            "TargetedDomainProtectionAction": "Quarantine",
            "MailboxIntelligenceProtectionAction": "Quarantine",
            "EnableFirstContactSafetyTips": True,
            "EnableSimilarUsersSafetyTips": True,
            "EnableSimilarDomainsSafetyTips": True,
            "EnableUnusualCharactersSafetyTips": True,
            "HonorDmarcPolicy": True
        }
        global_pass = False
        for policy in policies:
            policy_pass = True
            failed_fields = []
            for key, desired_value in expected_values.items():
                current_value = policy.get(key)
                if current_value != desired_value:
                    failed_fields.append((key, current_value, desired_value))
                    policy_pass = False
            targeted_users = policy.get("TargetedUsersToProtect")
            if not targeted_users or (isinstance(targeted_users, list) and len(targeted_users) == 0):
                failed_fields.append(("TargetedUsersToProtect", targeted_users, "Non-empty user list"))
                policy_pass = False
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.get("Name", "Unknown"),
                resource_id=policy.get("Name", "Unknown"),
                resource_location="global",
            )
            if policy_pass:
                report.status = "PASS"
                report.status_extended = (
                    f"Anti-Phishing policy '{policy.get('Name', 'Unknown')}' is correctly configured."
                )
                global_pass = True
            else:
                report.status = "FAIL"
                details = "; ".join([
                    f"{field}: {actual} (expected: {expected})" for field, actual, expected in failed_fields
                ])
                report.status_extended = (
                    f"Anti-Phishing policy '{policy.get('Name', 'Unknown')}' is NOT correctly configured. Issues: {details}"
                )
            findings.append(report)
        return findings
