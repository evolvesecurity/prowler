from typing import List
from prowler.lib.check.models import Check, CheckReportM365
import json
from prowler.providers.common.provider import Provider
import re

class teams_defender_reporting_policies(Check):
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
        # Teams Messaging Policy
        result_teams = provider.session.execute("Get-CsTeamsMessagingPolicy -Identity Global | Select-Object AllowSecurityEndUserReporting | ConvertTo-Json")
        if isinstance(result_teams, dict):
            teams_policy = result_teams
        else:
            json_str_teams = extract_json_from_output(str(result_teams))
            try:
                teams_policy = json.loads(json_str_teams)
            except Exception as e:
                teams_policy = {}
        allow_reporting = teams_policy.get("AllowSecurityEndUserReporting", None)
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"AllowSecurityEndUserReporting": allow_reporting},
            resource_name="AllowSecurityEndUserReporting",
            resource_id="AllowSecurityEndUserReporting",
            resource_location="global",
        )
        if allow_reporting is True:
            report.status = "PASS"
            report.status_extended = "AllowSecurityEndUserReporting is set to True."
        else:
            report.status = "FAIL"
            report.status_extended = "AllowSecurityEndUserReporting is not set to True."
        findings.append(report)
        # Defender Report Submission Policy
        result_defender = provider.session.execute(
            "Get-ReportSubmissionPolicy | Select-Object ReportJunkToCustomizedAddress, ReportNotJunkToCustomizedAddress, ReportPhishToCustomizedAddress, ReportChatMessageEnabled, ReportChatMessageToCustomizedAddressEnabled | ConvertTo-Json -Depth 10"
        )
        if isinstance(result_defender, dict):
            defender_policy = result_defender
        else:
            json_str_defender = extract_json_from_output(str(result_defender))
            try:
                defender_policy = json.loads(json_str_defender)
            except Exception as e:
                defender_policy = {}
        expected = {
            "ReportJunkToCustomizedAddress": True,
            "ReportNotJunkToCustomizedAddress": True,
            "ReportPhishToCustomizedAddress": True,
            "ReportChatMessageEnabled": False,
            "ReportChatMessageToCustomizedAddressEnabled": True
        }
        for key, expected_value in expected.items():
            actual = defender_policy.get(key, None)
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={key: actual},
                resource_name=key,
                resource_id=key,
                resource_location="global",
            )
            if actual == expected_value:
                report.status = "PASS"
                report.status_extended = f"{key} is set to {expected_value}."
            else:
                report.status = "FAIL"
                report.status_extended = f"{key} is not set to {expected_value}."
            findings.append(report)
        return findings

def extract_json_from_output(output: str) -> str:
    match = re.search(r'({.*})', output, re.DOTALL)
    if match:
        return match.group(1)
    return '{}' 