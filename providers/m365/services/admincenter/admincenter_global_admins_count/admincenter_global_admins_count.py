from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class admincenter_global_admins_count(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        client_id = getattr(provider, 'client_id', None)
        if not client_id and hasattr(provider, '_credentials'):
            client_id = getattr(provider._credentials, 'client_id', None)
        tenant_id = getattr(provider, 'tenant_id', None)
        if not tenant_id and hasattr(provider, '_credentials'):
            tenant_id = getattr(provider._credentials, 'tenant_id', None)
        # Import only the required Microsoft.Graph submodules
        import_cmd = (
            "Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue; "
            "Import-Module Microsoft.Graph.DirectoryRoles -ErrorAction SilentlyContinue"
        )
        provider.session.execute(import_cmd)
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        auth_args = M365PowerShell.get_mg_graph_auth_args(provider._credentials)
        connect_cmd = f"Connect-MgGraph {auth_args}"
        provider.session.execute(connect_cmd)
        # Use PowerShell to get the count of Global Admins, with error output
        ps_command = (
            "$globalAdminRole = Get-MgDirectoryRole -Filter \"RoleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'\"; "
            "if ($globalAdminRole) { "
            "  $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id; "
            "  $globalAdmins.AdditionalProperties.Count "
            "} else { "
            "  Write-Output 'NOT_FOUND' "
            "}"
        )
        result = provider.session.execute(ps_command)
        if isinstance(result, dict):
            result = result.get("output", "")
        if result == 'NOT_FOUND' or not result:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Global Administrators",
                resource_id="GlobalAdmins",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Global Admin Role not found or error occurred. Output: " + str(result)
            findings.append(report)
            return findings
        try:
            admin_count = int(result)
        except Exception:
            admin_count = 0
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Global Administrators",
            resource_id="GlobalAdmins",
            resource_location="global",
        )
        if admin_count > 8:
            report.status = "FAIL"
            report.status_extended = f"There are {admin_count} Global Administrators assigned."
        else:
            report.status = "PASS"
            report.status_extended = f"There are {admin_count} Global Administrators assigned."
        findings.append(report)
        try:
            provider.session.execute("Disconnect-MgGraph -ErrorAction SilentlyContinue")
        except Exception:
            pass
        try:
            provider.session.execute("Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue")
        except Exception:
            pass
        return findings 