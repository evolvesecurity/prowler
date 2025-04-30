from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class admincenter_internal_phishing_protection(Check):
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
        # Call the beta endpoint for Forms settings
        ps_command = (
            "$endpoint = 'https://graph.microsoft.com/beta/admin/Forms/settings'; "
            "$response = Invoke-MgGraphRequest -Uri $endpoint -Method GET; "
            "$response | ConvertTo-Json -Depth 10"
        )
        result = provider.session.execute(ps_command)
        response = None
        if isinstance(result, dict):
            if "isInOrgFormsPhishingScanEnabled" in result:
                response = result
            else:
                result = result.get("output", "")
        if not result and not response:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Internal Phishing Protection",
                resource_id="InternalPhishingProtection",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Could not retrieve Forms settings."
            findings.append(report)
            return findings
        if not response:
            try:
                import json
                response = json.loads(result)
            except Exception:
                response = None
        if not response or "isInOrgFormsPhishingScanEnabled" not in response:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=response if response else {},
                resource_name="Internal Phishing Protection",
                resource_id="InternalPhishingProtection",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "'isInOrgFormsPhishingScanEnabled' not found in response."
            findings.append(report)
            return findings
        phishing_scan_enabled = response["isInOrgFormsPhishingScanEnabled"]
        resource = {
            "is_in_org_forms_phishing_scan_enabled": phishing_scan_enabled,
        }
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=resource,
            resource_name="Internal Phishing Protection",
            resource_id="InternalPhishingProtection",
            resource_location="global",
        )
        if phishing_scan_enabled:
            report.status = "PASS"
            report.status_extended = "Internal Phishing Protection is enabled ('isInOrgFormsPhishingScanEnabled' is True)."
        else:
            report.status = "FAIL"
            report.status_extended = "'isInOrgFormsPhishingScanEnabled' is not True."
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
