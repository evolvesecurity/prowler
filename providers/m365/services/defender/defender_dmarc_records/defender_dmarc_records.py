from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json
import multiprocessing
import subprocess

def dns_query(domain, queue):
    try:
        ps_command = f"Resolve-DnsName -Name {domain} -Type TXT -ErrorAction Stop | ConvertTo-Json"
        completed = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True, text=True, timeout=10
        )
        if completed.returncode == 0:
            queue.put(completed.stdout)
        else:
            queue.put(Exception(completed.stderr))
    except Exception as e:
        queue.put(e)

class defender_dmarc_records(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
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
                resource_name="DMARC Record",
                resource_id="DMARCRecord",
                resource_location="global",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No domains found in DKIM configurations."
            )
            findings.append(report)
            return findings
        for domain in domains:
            dmarc_domain = f"_dmarc.{domain}"
            queue = multiprocessing.Queue()
            process = multiprocessing.Process(target=dns_query, args=(dmarc_domain, queue))
            process.start()
            process.join(12)
            if process.is_alive():
                process.terminate()
                process.join()
                status = "FAIL"
                status_extended = f"DMARC Record for {dmarc_domain} not found."
            else:
                try:
                    dmarc_result = queue.get_nowait()
                    if isinstance(dmarc_result, Exception):
                        status = "FAIL"
                        status_extended = f"DMARC Record for {dmarc_domain} not found."
                    else:
                        found = False
                        if isinstance(dmarc_result, str):
                            try:
                                dmarc_json = json.loads(dmarc_result)
                                if dmarc_json:
                                    found = True
                            except Exception as e:
                                found = False
                        elif isinstance(dmarc_result, list) or isinstance(dmarc_result, dict):
                            found = bool(dmarc_result)
                        if found:
                            status = "PASS"
                            status_extended = f"DMARC Record for {dmarc_domain} found."
                        else:
                            status = "FAIL"
                            status_extended = f"DMARC Record for {dmarc_domain} not found."
                except Exception as e:
                    status = "FAIL"
                    status_extended = f"DMARC Record for {dmarc_domain} not found."
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
        try:
            provider.session.execute("Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue")
        except Exception:
            pass
        return findings
