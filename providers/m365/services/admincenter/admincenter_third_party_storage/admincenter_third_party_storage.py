from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell

class admincenter_third_party_storage(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        client_id = getattr(provider, 'client_id', None)
        # Connect to Microsoft Graph using M365PowerShell instance
        ps = M365PowerShell(provider._credentials)
        ps.connect_mg_graph()
        # Query for service principals with the specified App ID
        app_id = "c1f33bc0-bdb4-4248-ba9b-096807ddb43e"
        ps_command = (
            f"$endpoint = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq \'{app_id}\''; "
            "$response = Invoke-MgGraphRequest -Uri $endpoint -Method GET; "
            "$response | ConvertTo-Json -Depth 10"
        )
        result = provider.session.execute(ps_command)
        response = None
        if isinstance(result, dict):
            if "value" in result:
                response = result
            else:
                result = result.get("output", "")
        # Treat empty output as PASS (no service principal exists)
        if (not result and not response) or (isinstance(result, str) and result.strip() == ''):
            resource = {
                "app_id": app_id,
                "service_principals": [],
            }
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=resource,
                resource_name="Third Party Storage",
                resource_id="ThirdPartyStorage",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = f"No service principal exists with App ID {app_id}."
            findings.append(report)
            return findings
        if not response:
            try:
                import json
                response = json.loads(result)
            except Exception as e:
                response = None
        if not response or "value" not in response:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=response if response else {},
                resource_name="Third Party Storage",
                resource_id="ThirdPartyStorage",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "Service principal information could not be determined."
            findings.append(report)
            return findings
        service_principals = response["value"]
        if service_principals and len(service_principals) > 0:
            display_names = [sp.get("displayName", "Unknown") for sp in service_principals]
            resource = {
                "app_id": app_id,
                "service_principals": display_names,
            }
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=resource,
                resource_name="Third Party Storage",
                resource_id="ThirdPartyStorage",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = (
                f"The following service principal(s) exist with App ID {app_id}: " + ", ".join(display_names)
            )
            findings.append(report)
        else:
            resource = {
                "app_id": app_id,
                "service_principals": [],
            }
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=resource,
                resource_name="Third Party Storage",
                resource_id="ThirdPartyStorage",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = f"No service principal exists with App ID {app_id}."
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
