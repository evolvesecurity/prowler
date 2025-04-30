from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_dynamic_guest_group(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Groups -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgGroup | Where-Object { $_.GroupTypes -contains 'DynamicMembership' } | Select-Object DisplayName,GroupTypes,MembershipRule | ConvertTo-Json")
        if isinstance(result, str):
            try:
                groups = json.loads(result)
                if isinstance(groups, dict):
                    groups = [groups]
            except Exception as e:
                groups = []
        elif isinstance(result, list):
            groups = result
        elif isinstance(result, dict):
            groups = [result]
        else:
            groups = []
        if groups:
            for group in groups:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=group,
                    resource_name=group.get("DisplayName", "Unknown"),
                    resource_id=group.get("DisplayName", "Unknown"),
                    resource_location="global",
                )
                report.status = "PASS"
                report.status_extended = f"Dynamic guest group found: {group.get('DisplayName', 'Unknown')}"
                findings.append(report)
        else:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Dynamic Guest Group",
                resource_id="DynamicGuestGroup",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No dynamic guest groups found."
            findings.append(report)
        return findings
