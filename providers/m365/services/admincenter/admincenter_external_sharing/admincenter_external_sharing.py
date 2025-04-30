from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class admincenter_external_sharing(Check):
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
            "Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue"
        )
        provider.session.execute(import_cmd)
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_exo_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_exo_cmd)
        # Get the Default Sharing Policy
        ps_command = (
            "Get-SharingPolicy -Identity 'Default Sharing Policy' | Select-Object Identity, Enabled | ConvertTo-Json"
        )
        result = provider.session.execute(ps_command)
        if isinstance(result, dict):
            result = result.get("output", "")
        if not result:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Default Sharing Policy",
                resource_id="DefaultSharingPolicy",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No External Sharing Policy found."
            findings.append(report)
            return findings
        try:
            import json
            policy = None
            if isinstance(result, list):
                if result and isinstance(result[0], dict):
                    policy = result[0]
                else:
                    result = "".join(result)
                    policy = json.loads(result)
            elif isinstance(result, str):
                policy = json.loads(result)
            elif isinstance(result, dict):
                policy = result
        except Exception:
            policy = None
        if not policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Default Sharing Policy",
                resource_id="DefaultSharingPolicy",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No External Sharing Policy found."
            findings.append(report)
            return findings
        resource = {
            "identity": policy.get("Identity", "Default Sharing Policy"),
            "enabled": policy.get("Enabled", None),
        }
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=resource,
            resource_name=resource["identity"],
            resource_id=resource["identity"],
            resource_location="global",
        )
        if resource["enabled"] is False:
            report.status = "PASS"
            report.status_extended = f"External sharing is disabled in the Default Sharing Policy."
        else:
            report.status = "FAIL"
            report.status_extended = f"External sharing is enabled in the Default Sharing Policy."
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
