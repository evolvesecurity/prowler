from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class admincenter_public_groups(Check):
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
            "Import-Module Microsoft.Graph.Groups -ErrorAction SilentlyContinue"
        )
        provider.session.execute(import_cmd)
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        graph_auth_args = M365PowerShell.get_mg_graph_auth_args(provider._credentials)
        connect_cmd = f"Connect-MgGraph {graph_auth_args}"
        provider.session.execute(connect_cmd)
        # PowerShell to get all groups with DisplayName, Id, and Visibility
        ps_command = (
            "Get-MgGroup | Select-Object DisplayName, Id, Visibility | ConvertTo-Json"
        )
        result = provider.session.execute(ps_command)
        if isinstance(result, dict):
            result = result.get("output", "")
        if not result:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Public Groups",
                resource_id="PublicGroups",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Could not retrieve groups."
            findings.append(report)
            return findings
        try:
            import json
            groups = []
            if isinstance(result, list):
                if result and isinstance(result[0], dict):
                    groups = result
                else:
                    result = "".join(result)
                    groups = json.loads(result)
            elif isinstance(result, str):
                groups = json.loads(result)
            elif isinstance(result, dict):
                groups = [result]
        except Exception as e:
            groups = []
        for group in groups:
            # Map keys to match expected structure
            mapped_group = {
                "name": group.get("DisplayName", "Unknown"),
                "id": group.get("Id", "Unknown"),
                "visibility": group.get("Visibility", "Unknown"),
            }
            if mapped_group["visibility"] and str(mapped_group["visibility"]).lower() == "public":
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=mapped_group,
                    resource_name=mapped_group["name"],
                    resource_id=mapped_group["id"],
                    resource_location="global",
                )
                report.status = "FAIL"
                report.status_extended = f"Group {mapped_group['name']} has Public visibility and should be Private."
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
