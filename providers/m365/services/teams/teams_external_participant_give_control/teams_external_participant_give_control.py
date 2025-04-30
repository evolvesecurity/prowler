from typing import List
from prowler.lib.check.models import Check, CheckReportM365
import json
import subprocess
import multiprocessing
import re

def external_participant_give_control_query(queue, client_id, certificate_thumbprint, tenant_id):
    try:
        ps_command = (
            f"Import-Module MicrosoftTeams -ErrorAction SilentlyContinue; "
            f"Connect-MicrosoftTeams -ApplicationId '{client_id}' -CertificateThumbprint '{certificate_thumbprint}' -TenantId '{tenant_id}'; "
            "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalParticipantGiveRequestControl | ConvertTo-Json"
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

class teams_external_participant_give_control(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        from prowler.providers.common.provider import Provider
        provider = Provider.get_global_provider()
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=external_participant_give_control_query,
            args=(queue, provider.client_id, provider.certificate_thumbprint, provider.tenant_id)
        )
        process.start()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join()
            value = None
            status = "FAIL"
            status_extended = "PowerShell query for AllowExternalParticipantGiveRequestControl timed out."
        else:
            try:
                result = queue.get_nowait()
                if isinstance(result, Exception):
                    value = None
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
                    value = config.get("AllowExternalParticipantGiveRequestControl", None)
                    if value is False:
                        status = "PASS"
                        status_extended = "AllowExternalParticipantGiveRequestControl is set to False."
                    else:
                        status = "FAIL"
                        status_extended = "AllowExternalParticipantGiveRequestControl is not set to False."
            except Exception as e:
                value = None
                status = "FAIL"
                status_extended = "Failed to retrieve PowerShell result."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"AllowExternalParticipantGiveRequestControl": value},
            resource_name="AllowExternalParticipantGiveRequestControl",
            resource_id="AllowExternalParticipantGiveRequestControl",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings 