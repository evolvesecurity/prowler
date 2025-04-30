from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell

class admincenter_idle_session_timeout(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        client_id = getattr(provider, 'client_id', None)
        if not client_id and hasattr(provider, '_credentials'):
            client_id = getattr(provider._credentials, 'client_id', None)
        tenant_id = getattr(provider, 'tenant_id', None)
        if not tenant_id and hasattr(provider, '_credentials'):
            tenant_id = getattr(provider._credentials, 'tenant_id', None)
        # Import required module
        import_cmd = (
            "Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue"
        )
        provider.session.execute(import_cmd)
        graph_auth_args = M365PowerShell.get_mg_graph_auth_args(provider._credentials)
        connect_graph_cmd = f"Connect-MgGraph {graph_auth_args}"
        graph_result = provider.session.execute(connect_graph_cmd)
        # Get all conditional access policies (with and without IdleSessionSignOut)
        ps_command_all = (
            "Get-MgIdentityConditionalAccessPolicy | Select-Object Id, DisplayName, State, SessionControls | ConvertTo-Json"
        )
        all_policies_result = provider.session.execute(ps_command_all)
        if isinstance(all_policies_result, dict):
            all_policies_result = all_policies_result.get("output", "")
        try:
            import json
            all_policies = []
            if isinstance(all_policies_result, list):
                if all_policies_result and isinstance(all_policies_result[0], dict):
                    all_policies = all_policies_result
                else:
                    all_policies_result = "".join(all_policies_result)
                    all_policies = json.loads(all_policies_result)
            elif isinstance(all_policies_result, str) and all_policies_result.strip():
                all_policies = json.loads(all_policies_result)
            elif isinstance(all_policies_result, dict):
                all_policies = [all_policies_result]
        except Exception as e:
            all_policies = []
        # Now get only those with IdleSessionSignOut
        ps_command_idle = (
            "Get-MgIdentityConditionalAccessPolicy | ForEach-Object { if ($_.SessionControls.IdleSessionSignOut -ne $null) { [PSCustomObject]@{ Id = $_.Id; DisplayName = $_.DisplayName; State = $_.State; IsEnabled = $_.SessionControls.IdleSessionSignOut.IsEnabled; SignOutAfterInSecs = $_.SessionControls.IdleSessionSignOut.SignOutAfterInSeconds; WarnAfterInSecs = $_.SessionControls.IdleSessionSignOut.WarnAfterInSeconds } } } | ConvertTo-Json"
        )
        idle_policies_result = provider.session.execute(ps_command_idle)
        if isinstance(idle_policies_result, dict):
            idle_policies_result = idle_policies_result.get("output", "")
        try:
            idle_policies = []
            if isinstance(idle_policies_result, list):
                if idle_policies_result and isinstance(idle_policies_result[0], dict):
                    idle_policies = idle_policies_result
                else:
                    idle_policies_result = "".join(idle_policies_result)
                    idle_policies = json.loads(idle_policies_result)
            elif isinstance(idle_policies_result, str) and idle_policies_result.strip():
                idle_policies = json.loads(idle_policies_result)
            elif isinstance(idle_policies_result, dict):
                idle_policies = [idle_policies_result]
        except Exception as e:
            idle_policies = []
        # If no policies at all
        if not all_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Idle Session Timeout",
                resource_id="IdleSessionTimeout",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Could not retrieve any conditional access policies."
            findings.append(report)
            return findings
        # If no policy has IdleSessionSignOut, FAIL for each policy
        if not idle_policies:
            for policy in all_policies:
                display_name = policy.get("DisplayName", "Unknown")
                policy_id = policy.get("Id", "Unknown")
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={"policy_id": policy_id, "display_name": display_name},
                    resource_name=display_name,
                    resource_id=policy_id,
                    resource_location="global",
                )
                report.status = "FAIL"
                report.status_extended = f"Policy '{display_name}' is missing idle session timeout."
                findings.append(report)
            return findings
        # If any enabled policy has IdleSessionSignOut and SignOutAfterInSeconds >= 3, PASS (only one needed)
        found_enabled_and_valid = False
        for policy in idle_policies:
            display_name = policy.get("DisplayName", "Unknown")
            policy_id = policy.get("Id", "Unknown")
            is_enabled = policy.get("IsEnabled", False)
            signout_after = policy.get("SignOutAfterInSecs", None)
            resource = {
                "policy_id": policy_id,
                "display_name": display_name,
                "is_enabled": is_enabled,
                "signout_after_in_seconds": signout_after,
            }
            if is_enabled and signout_after is not None and isinstance(signout_after, int) and signout_after >= 3:
                found_enabled_and_valid = True
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=resource,
                    resource_name=display_name,
                    resource_id=policy_id,
                    resource_location="global",
                )
                report.status = "PASS"
                report.status_extended = f"Policy '{display_name}' has Idle Session Timeout set to {signout_after} seconds (>= 3) and enabled."
                findings.append(report)
                return findings
        # If present but < 3 or not enabled, FAIL for each such policy
        for policy in idle_policies:
            display_name = policy.get("DisplayName", "Unknown")
            policy_id = policy.get("Id", "Unknown")
            is_enabled = policy.get("IsEnabled", False)
            signout_after = policy.get("SignOutAfterInSecs", None)
            resource = {
                "policy_id": policy_id,
                "display_name": display_name,
                "is_enabled": is_enabled,
                "signout_after_in_seconds": signout_after,
            }
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=resource,
                resource_name=display_name,
                resource_id=policy_id,
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = f"Policy '{display_name}' has Idle Session Timeout set to {signout_after} seconds (< 3) or not enabled."
            findings.append(report)
        return findings
        try:
            provider.session.execute("Disconnect-MgGraph -ErrorAction SilentlyContinue")
        except Exception:
            pass
        try:
            provider.session.execute("Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue")
        except Exception:
            pass
