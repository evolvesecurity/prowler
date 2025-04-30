from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
import json

class defender_dkim_signing(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        # Avoid duplicate -AppId and -Organization if already in exo_auth_args
        if "-AppId" in exo_auth_args or "-Organization" in exo_auth_args:
            connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        else:
            connect_cmd = (
                f"Connect-ExchangeOnline {exo_auth_args} "
                f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
            )
        print(f"[DEBUG] Connecting to ExchangeOnline: {connect_cmd}", flush=True)
        provider.session.execute(connect_cmd)
        dkim_result = provider.session.execute("Get-DkimSigningConfig | ConvertTo-Json")
        if isinstance(dkim_result, str):
            try:
                configs = json.loads(dkim_result)
                if isinstance(configs, dict):
                    configs = [configs]
            except Exception as e:
                configs = []
        elif isinstance(dkim_result, list):
            configs = dkim_result
        elif isinstance(dkim_result, dict):
            configs = [dkim_result]
        else:
            configs = []
        if not configs:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="DKIM Signing",
                resource_id="DKIMSigning",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No DKIM Signing Configurations found."
            )
            findings.append(report)
            return findings
        filtered_configs = [c for c in configs if not c.get("Domain", "").endswith(".onmicrosoft.com")]
        if not filtered_configs:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="DKIM Signing",
                resource_id="DKIMSigning",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No relevant domains found (excluding .onmicrosoft.com domains)."
            )
            findings.append(report)
            return findings
        all_enabled = True
        for config in filtered_configs:
            enabled = config.get("Enabled", False)
            domain = config.get("Domain", "Unknown")
            if enabled:
                status = "PASS"
                status_extended = f"DKIM Signing is Enabled for domain: {domain}"
            else:
                status = "FAIL"
                status_extended = f"DKIM Signing is Disabled for domain: {domain}"
                all_enabled = False
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=config,
                resource_name=domain,
                resource_id=domain,
                resource_location="global",
            )
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings
