from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_per_user_mfa_state(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        users_result = provider.session.execute("Get-MgUser -All:$true | Select-Object Id,DisplayName,UserPrincipalName | ConvertTo-Json")
        if isinstance(users_result, str):
            try:
                users = json.loads(users_result)
                if isinstance(users, dict):
                    users = [users]
            except Exception as e:
                users = []
        elif isinstance(users_result, list):
            users = users_result
        elif isinstance(users_result, dict):
            users = [users_result]
        else:
            users = []
        if not users:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Per-User MFA State",
                resource_id="PerUserMfaState",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No users found or unable to determine MFA state."
            findings.append(report)
            return findings
        for user in users:
            user_id = user.get("Id")
            display_name = user.get("DisplayName")
            upn = user.get("UserPrincipalName")
            try:
                mfa_state_result = provider.session.execute(
                    f"Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/users/{user_id}/authentication/requirements' -Method GET | ConvertTo-Json"
                )
                if isinstance(mfa_state_result, str):
                    try:
                        mfa_state = json.loads(mfa_state_result)
                    except Exception as e:
                        mfa_state = {}
                elif isinstance(mfa_state_result, dict):
                    mfa_state = mfa_state_result
                else:
                    mfa_state = {}
                per_user_mfa_state = mfa_state.get("perUserMfaState", "unknown")
            except Exception as e:
                per_user_mfa_state = "unknown"
            resource_name = display_name or upn or user_id or "unknown"
            resource_id = upn or user_id or "unknown"
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={
                    "DisplayName": display_name,
                    "UserPrincipalName": upn,
                    "PerUserMfaState": per_user_mfa_state
                },
                resource_name=resource_name,
                resource_id=resource_id,
                resource_location="global",
            )
            if per_user_mfa_state in ("enabled", "enforced"):
                report.status = "PASS"
                report.status_extended = f"User '{display_name or upn}' has MFA enabled."
            elif per_user_mfa_state == "disabled":
                report.status = "FAIL"
                report.status_extended = f"User '{display_name or upn}' does NOT have MFA enabled."
            else:
                report.status = "MANUAL"
                report.status_extended = f"Unable to determine MFA state for user '{display_name or upn}'."
            findings.append(report)
        return findings
