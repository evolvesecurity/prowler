from typing import List
from prowler.lib.check.models import Check, CheckReportM365
import json
import subprocess
import multiprocessing
import re

def skype_communication_query(queue, client_id, certificate_thumbprint, tenant_id):
    try:
        ps_command = (
            f"Import-Module MicrosoftTeams -ErrorAction SilentlyContinue; "
            f"Connect-MicrosoftTeams -ApplicationId '{client_id}' -CertificateThumbprint '{certificate_thumbprint}' -TenantId '{tenant_id}'; "
            "Get-CsTenantFederationConfiguration | Select-Object AllowPublicUsers | ConvertTo-Json"
        )
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

def extract_json_from_output(output: str) -> str:
    match = re.search(r'({.*})', output, re.DOTALL)
    if match:
        return match.group(1)
    return '{}'

class teams_skype_communication(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        from prowler.providers.common.provider import Provider
        provider = Provider.get_global_provider()
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=skype_communication_query,
            args=(queue, provider.client_id, provider.certificate_thumbprint, provider.tenant_id)
        )
        process.start()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join()
            allowed = None
            status = "FAIL"
            status_extended = "PowerShell query for AllowPublicUsers timed out."
        else:
            try:
                result = queue.get_nowait()
                if isinstance(result, Exception):
                    allowed = None
                    status = "FAIL"
                    status_extended = "PowerShell query failed."
                else:
                    if isinstance(result, str):
                        json_str = extract_json_from_output(result)
                        try:
                            config = json.loads(json_str)
                        except Exception as e:
                            config = {}
                    else:
                        config = result if result else {}
                    allowed = config.get("AllowPublicUsers", None)
                    if allowed is False:
                        status = "PASS"
                        status_extended = "AllowPublicUsers is set to False."
                    else:
                        status = "FAIL"
                        status_extended = "AllowPublicUsers is not set to False."
            except Exception as e:
                allowed = None
                status = "FAIL"
                status_extended = "Failed to retrieve PowerShell result."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"AllowPublicUsers": allowed},
            resource_name="AllowPublicUsers",
            resource_id="AllowPublicUsers",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings 