from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider

class entra_password_hash_sync(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-MgOrganization | Select-Object -ExpandProperty OnPremisesSyncEnabled | ConvertTo-Json")
        if isinstance(result, str):
            hash_sync_status = result.strip().lower() == 'true'
        else:
            hash_sync_status = bool(result)
        if hash_sync_status:
            status = "PASS"
            status_extended = "Password Hash Sync is enabled."
        else:
            status = "FAIL"
            status_extended = "Password Hash Sync is disabled."
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={"OnPremisesSyncEnabled": hash_sync_status},
            resource_name="OnPremisesSyncEnabled",
            resource_id="OnPremisesSyncEnabled",
            resource_location="global",
        )
        report.status = status
        report.status_extended = status_extended
        findings.append(report)
        return findings
