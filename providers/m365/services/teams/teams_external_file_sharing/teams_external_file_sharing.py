from typing import List
from prowler.lib.check.models import Check, CheckReportM365
import json
import subprocess
import multiprocessing
import re

def external_file_sharing_query(queue, client_id, certificate_thumbprint, tenant_id):
    try:
        ps_command = (
            f"Import-Module MicrosoftTeams -ErrorAction SilentlyContinue; "
            f"Connect-MicrosoftTeams -ApplicationId '{client_id}' -CertificateThumbprint '{certificate_thumbprint}' -TenantId '{tenant_id}'; "
            "Get-CsTeamsClientConfiguration | Select-Object AllowDropbox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte | ConvertTo-Json -Depth 10"
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

class teams_external_file_sharing(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        from prowler.providers.common.provider import Provider
        provider = Provider.get_global_provider()
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=external_file_sharing_query,
            args=(queue, provider.client_id, provider.certificate_thumbprint, provider.tenant_id)
        )
        process.start()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join()
            config = []
        else:
            try:
                result = queue.get_nowait()
                if isinstance(result, Exception):
                    config = []
                else:
                    json_str = extract_json_from_output(result)
                    try:
                        config = json.loads(json_str)
                    except Exception as e:
                        config = []
            except Exception as e:
                config = []
        if isinstance(config, dict):
            config = [config]
        for conf in config:
            for provider_name in ["AllowDropbox", "AllowBox", "AllowGoogleDrive", "AllowShareFile", "AllowEgnyte"]:
                allowed = conf.get(provider_name, False)
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={provider_name: allowed},
                    resource_name=provider_name,
                    resource_id=provider_name,
                    resource_location="global",
                )
                if allowed:
                    report.status = "FAIL"
                    report.status_extended = f"{provider_name} is enabled."
                else:
                    report.status = "PASS"
                    report.status_extended = f"{provider_name} is disabled."
                findings.append(report)
        return findings 