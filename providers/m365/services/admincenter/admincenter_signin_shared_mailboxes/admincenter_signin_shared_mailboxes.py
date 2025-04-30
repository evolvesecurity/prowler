from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class admincenter_signin_shared_mailboxes(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        client_id = getattr(provider, 'client_id', None)
        if not client_id and hasattr(provider, '_credentials'):
            client_id = getattr(provider._credentials, 'client_id', None)
        tenant_id = getattr(provider, 'tenant_id', None)
        if not tenant_id and hasattr(provider, '_credentials'):
            tenant_id = getattr(provider._credentials, 'tenant_id', None)
        organization = getattr(provider, 'organization', None)
        if not organization:
            print("[ERROR] The 'organization' parameter is missing. Please provide your tenant's verified domain (e.g., contoso.onmicrosoft.com).")
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Shared Mailboxes Sign-In",
                resource_id="SharedMailboxesSignIn",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Missing organization parameter for Exchange Online connection."
            findings.append(report)
            return findings
        # Import required modules
        import_cmd = (
            "Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue; "
            "Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue"
        )
        provider.session.execute(import_cmd)
        # Connect to Exchange Online and Graph
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_exo_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        exo_result = provider.session.execute(connect_exo_cmd)
        graph_auth_args = M365PowerShell.get_mg_graph_auth_args(provider._credentials)
        connect_graph_cmd = f"Connect-MgGraph {graph_auth_args}"
        graph_result = provider.session.execute(connect_graph_cmd)
        # Get all shared mailboxes
        get_mailboxes_cmd = (
            "Get-EXOMailbox -RecipientTypeDetails SharedMailbox | ConvertTo-Json"
        )
        mailboxes_result = provider.session.execute(get_mailboxes_cmd)
        ps_command = (
            "$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox; "
            "$SignInData = $MBX | ForEach-Object { Get-MgUser -UserId $_.ExternalDirectoryObjectId -Property DisplayName, UserPrincipalName, AccountEnabled }; "
            "$SignInData | ConvertTo-Json"
        )
        result = provider.session.execute(ps_command)
        if isinstance(result, dict):
            result = result.get("output", "")
        if not result:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Shared Mailboxes Sign-In",
                resource_id="SharedMailboxesSignIn",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Could not retrieve shared mailbox sign-in data."
            findings.append(report)
            return findings
        try:
            import json
            signins = []
            if isinstance(result, list):
                if result and isinstance(result[0], dict):
                    signins = result
                else:
                    result = "".join(result)
                    signins = json.loads(result)
            elif isinstance(result, str):
                signins = json.loads(result)
            elif isinstance(result, dict):
                signins = [result]
        except Exception as e:
            signins = []
        found_enabled = False
        for signin in signins:
            display_name = signin.get("DisplayName", "Unknown")
            user_principal_name = signin.get("UserPrincipalName", "Unknown")
            account_enabled = signin.get("AccountEnabled", False)
            resource = {
                "display_name": display_name,
                "user_principal_name": user_principal_name,
                "account_enabled": account_enabled,
            }
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=resource,
                resource_name=display_name,
                resource_id=user_principal_name,
                resource_location="global",
            )
            if account_enabled:
                report.status = "FAIL"
                report.status_extended = f"Shared mailbox '{display_name}' ({user_principal_name}) has sign-in enabled (AccountEnabled=True)."
                found_enabled = True
            else:
                report.status = "PASS"
                report.status_extended = f"Shared mailbox '{display_name}' ({user_principal_name}) does not have sign-in enabled."
            findings.append(report)
        if not signins:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Shared Mailboxes Sign-In",
                resource_id="SharedMailboxesSignIn",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = "No shared mailboxes found."
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
