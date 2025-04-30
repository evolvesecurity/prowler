from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class admincenter_apps_and_services_settings(Check):
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
            "Import-Module Microsoft.Graph.Beta.Admin -ErrorAction SilentlyContinue"
        )
        provider.session.execute(import_cmd)
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        graph_auth_args = M365PowerShell.get_mg_graph_auth_args(provider._credentials)
        connect_graph_cmd = f"Connect-MgGraph {graph_auth_args}"
        provider.session.execute(connect_graph_cmd)
        # Call the beta endpoint for apps and services settings
        ps_command = (
            "$endpoint = 'https://graph.microsoft.com/beta/admin/appsAndServices'; "
            "$response = Invoke-MgGraphRequest -Uri $endpoint -Method GET; "
            "$response | ConvertTo-Json -Depth 10"
        )
        result = provider.session.execute(ps_command)
        response = None
        if isinstance(result, dict):
            # If result already contains 'settings', use it directly
            if "settings" in result:
                response = result
            else:
                result = result.get("output", "")
        if not result and not response:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Apps and Services Settings",
                resource_id="AppsAndServicesSettings",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Could not retrieve Apps and Services settings."
            findings.append(report)
            return findings
        if not response:
            try:
                import json
                response = json.loads(result)
            except Exception as e:
                response = None
        if not response or "settings" not in response:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=response if response else {},
                resource_name="Apps and Services Settings",
                resource_id="AppsAndServicesSettings",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "API response does not contain 'settings'."
            findings.append(report)
            return findings
        settings = response["settings"]
        is_office_store_enabled = settings.get("isOfficeStoreEnabled", None)
        is_app_and_services_trial_enabled = settings.get("isAppAndServicesTrialEnabled", None)
        resource = {
            "is_office_store_enabled": is_office_store_enabled,
            "is_app_and_services_trial_enabled": is_app_and_services_trial_enabled,
        }
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=resource,
            resource_name="Apps and Services Settings",
            resource_id="AppsAndServicesSettings",
            resource_location="global",
        )
        if is_office_store_enabled or is_app_and_services_trial_enabled:
            report.status = "FAIL"
            if is_office_store_enabled:
                report.status_extended = "Office Store is enabled."
            if is_app_and_services_trial_enabled:
                if report.status_extended:
                    report.status_extended += " App and Services Trial is enabled."
                else:
                    report.status_extended = "App and Services Trial is enabled."
        else:
            report.status = "PASS"
            report.status_extended = "Both Office Store and App & Services Trial are disabled."
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
