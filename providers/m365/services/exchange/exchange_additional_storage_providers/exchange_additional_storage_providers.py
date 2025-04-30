from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_additional_storage_providers(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                policies = json.loads(result)
            except Exception as e:
                policies = []
        else:
            policies = result if result else []
        if not policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"OwaMailboxPolicies": []},
                resource_name="AdditionalStorageProviders",
                resource_id="AdditionalStorageProviders",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = "No OwaMailboxPolicy found."
            findings.append(report)
        else:
            if isinstance(policies, dict):
                policies = [policies]
            fail_found = False
            for policy in policies:
                name = policy.get('Name', 'Unknown')
                additional_storage = policy.get('AdditionalStorageProvidersAvailable', False)
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={"Name": name, "AdditionalStorageProvidersAvailable": additional_storage},
                    resource_name=name,
                    resource_id=name,
                    resource_location="global",
                )
                if additional_storage:
                    report.status = "FAIL"
                    report.status_extended = f"OwaMailboxPolicy '{name}' has AdditionalStorageProvidersAvailable set to True."
                    fail_found = True
                else:
                    report.status = "PASS"
                    report.status_extended = f"OwaMailboxPolicy '{name}' has AdditionalStorageProvidersAvailable set to False."
                findings.append(report)
        return findings
