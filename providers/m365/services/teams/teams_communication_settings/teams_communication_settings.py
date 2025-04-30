from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json
import re

class teams_communication_settings(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module MicrosoftTeams -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MicrosoftTeams -ApplicationId '{provider.client_id}' "
            f"-CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-TenantId '{provider.tenant_id}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumer | ConvertTo-Json")
        if isinstance(result, dict):
            config = result
        else:
            json_str = extract_json_from_output(str(result))
            try:
                config = json.loads(json_str)
            except Exception as e:
                config = {}
        allowed = config.get("AllowTeamsConsumer", None)
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"AllowTeamsConsumer": allowed},
            resource_name="AllowTeamsConsumer",
            resource_id="AllowTeamsConsumer",
            resource_location="global",
        )
        if allowed is False:
            report.status = "PASS"
            report.status_extended = "AllowTeamsConsumer is set to False."
        elif allowed is True:
            report.status = "FAIL"
            report.status_extended = "AllowTeamsConsumer is set to True."
        else:
            report.status = "MANUAL"
            report.status_extended = "Unknown value for AllowTeamsConsumer."
        findings.append(report)
        return findings

def extract_json_from_output(output: str) -> str:
    match = re.search(r'({.*})', output, re.DOTALL)
    if match:
        return match.group(1)
    return '{}' 