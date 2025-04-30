from typing import List
from prowler.lib.check.models import Check, CheckReportM365
import json
from prowler.providers.common.provider import Provider
import re

class teams_dialin_users_bypass_lobby(Check):
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
        result = provider.session.execute("Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowPSTNUsersToBypassLobby | ConvertTo-Json")
        if isinstance(result, dict):
            config = result
        else:
            json_str = extract_json_from_output(str(result))
            try:
                config = json.loads(json_str)
            except Exception as e:
                config = {}
        value = config.get("AllowPSTNUsersToBypassLobby", None)
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"AllowPSTNUsersToBypassLobby": value},
            resource_name="AllowPSTNUsersToBypassLobby",
            resource_id="AllowPSTNUsersToBypassLobby",
            resource_location="global",
        )
        if value is False:
            report.status = "PASS"
            report.status_extended = "AllowPSTNUsersToBypassLobby is set to False."
        else:
            report.status = "FAIL"
            report.status_extended = "AllowPSTNUsersToBypassLobby is not set to False."
        findings.append(report)
        return findings

def extract_json_from_output(output: str) -> str:
    match = re.search(r'({.*})', output, re.DOTALL)
    if match:
        return match.group(1)
    return '{}' 