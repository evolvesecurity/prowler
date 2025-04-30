from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
import json

class defender_connection_filter_safe_list(Check):
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
        result = provider.session.execute("Get-HostedConnectionFilterPolicy -Identity Default | ConvertTo-Json")
        if isinstance(result, str):
            try:
                policy = json.loads(result)
            except Exception as e:
                policy = {}
        elif isinstance(result, dict):
            policy = result
        else:
            policy = {}
        enable_safe_list = policy.get("EnableSafeList")
        if enable_safe_list is False:
            status = "PASS"
            status_extended = "EnableSafeList is set to False."
        else:
            status = "FAIL"
            status_extended = f"EnableSafeList is not set to False: {enable_safe_list}"
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=policy,
            resource_name=policy.get("Identity", "Default"),
            resource_id=policy.get("Identity", "Default"),
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
