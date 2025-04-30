from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class admincenter_password_expiration_policy(Check):
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
            "Import-Module Microsoft.Graph.Domains -ErrorAction SilentlyContinue"
        )
        provider.session.execute(import_cmd)
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        graph_auth_args = M365PowerShell.get_mg_graph_auth_args(provider._credentials)
        connect_graph_cmd = f"Connect-MgGraph {graph_auth_args}"
        graph_result = provider.session.execute(connect_graph_cmd)
        # Get all domains and their password validity period
        ps_command = (
            "Get-MgDomain | Select-Object Id, PasswordValidityPeriodInDays | ConvertTo-Json"
        )
        result = provider.session.execute(ps_command)
        if isinstance(result, dict):
            result = result.get("output", "")
        if not result:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Password Expiration Policy",
                resource_id="PasswordExpirationPolicy",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = "Could not retrieve domain password expiration data."
            findings.append(report)
            return findings
        try:
            import json
            domains = []
            if isinstance(result, list):
                if result and isinstance(result[0], dict):
                    domains = result
                else:
                    result = "".join(result)
                    domains = json.loads(result)
            elif isinstance(result, str):
                domains = json.loads(result)
            elif isinstance(result, dict):
                domains = [result]
        except Exception as e:
            domains = []
        for domain in domains:
            domain_id = domain.get("Id", "Unknown")
            validity = domain.get("PasswordValidityPeriodInDays", None)
            resource = {
                "domain_id": domain_id,
                "password_validity_period_in_days": validity,
            }
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=resource,
                resource_name=domain_id,
                resource_id=domain_id,
                resource_location="global",
            )
            if validity is not None and validity < 365:
                report.status = "FAIL"
                report.status_extended = f"Domain '{domain_id}' has password expiration set to {validity} days (< 365)."
            else:
                report.status = "PASS"
                report.status_extended = f"Domain '{domain_id}' has password expiration set to {validity} days (>= 365) or not set."
            findings.append(report)
        if not domains:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Password Expiration Policy",
                resource_id="PasswordExpirationPolicy",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = "No domain data found."
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
