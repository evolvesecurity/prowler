from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell

class defender_spf_records(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = f"Connect-ExchangeOnline {exo_auth_args}"
        provider.session.execute(connect_cmd)
        dkim_result = provider.session.execute("Get-DkimSigningConfig | Select-Object -ExpandProperty Domain | ConvertTo-Json")
        if isinstance(dkim_result, str):
            try:
                domains = json.loads(dkim_result)
                if isinstance(domains, str):
                    domains = [domains]
            except Exception as e:
                domains = []
        elif isinstance(dkim_result, list):
            domains = dkim_result
        elif isinstance(dkim_result, dict):
            domains = [dkim_result]
        else:
            domains = []
        if not domains:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="SPF Record",
                resource_id="SPFRecord",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No domains found in DKIM configurations. Skipping SPF check."
            )
            findings.append(report)
            return findings
        all_pass = True
        for domain in domains:
            try:
                spf_result = provider.session.execute(
                    f"Resolve-DnsName -Name {domain} -Type TXT -ErrorAction Stop | Where-Object {{ $_.Strings -like '*v=spf1 include:spf.protection.outlook.com*' }} | ConvertTo-Json"
                )
                found = False
                if isinstance(spf_result, str):
                    try:
                        spf_json = json.loads(spf_result)
                        if spf_json:
                            found = True
                    except Exception as e:
                        found = False
                elif isinstance(spf_result, list) or isinstance(spf_result, dict):
                    found = bool(spf_result)
                if found:
                    status = "PASS"
                    status_extended = f"SPF Record exists for {domain}."
                else:
                    status = "FAIL"
                    status_extended = f"SPF Record does not exist for {domain}."
                    all_pass = False
            except Exception as e:
                status = "FAIL"
                status_extended = f"Failed to resolve SPF record for {domain}: {e}"
                all_pass = False
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"domain": domain},
                resource_name=domain,
                resource_id=domain,
                resource_location="global",
            )
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings
