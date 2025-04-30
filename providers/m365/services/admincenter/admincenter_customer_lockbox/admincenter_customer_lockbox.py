from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class admincenter_customer_lockbox(Check):
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
        # Get the Customer Lockbox configuration
        ps_command = (
            "Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled | ConvertTo-Json"
        )
        result = provider.session.execute(ps_command)
        response = None
        if isinstance(result, dict):
            # Handle both 'CustomerLockBoxEnabled' and 'CustomerLockboxEnabled' (case-insensitive)
            for k in result:
                if k.lower() == "customerlockboxenabled":
                    response = {"CustomerLockBoxEnabled": result[k]}
                    break
            if response is None:
                result = result.get("output", "")
        if not result and not response:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Customer Lockbox",
                resource_id="CustomerLockbox",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Could not retrieve Customer Lockbox configuration."
            findings.append(report)
            return findings
        if not response:
            try:
                import json
                response = json.loads(result)
            except Exception as e:
                response = None
        if not response or "CustomerLockBoxEnabled" not in response:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=response if response else {},
                resource_name="Customer Lockbox",
                resource_id="CustomerLockbox",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "Customer Lockbox status could not be determined."
            findings.append(report)
            return findings
        lockbox_enabled = response["CustomerLockBoxEnabled"]
        resource = {
            "customer_lockbox_enabled": lockbox_enabled,
        }
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=resource,
            resource_name="Customer Lockbox",
            resource_id="CustomerLockbox",
            resource_location="global",
        )
        if lockbox_enabled is True:
            report.status = "PASS"
            report.status_extended = "Customer Lockbox is enabled."
        elif lockbox_enabled is False:
            report.status = "FAIL"
            report.status_extended = "Customer Lockbox is disabled."
        else:
            report.status = "FAIL"
            report.status_extended = "Customer Lockbox status could not be determined."
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
