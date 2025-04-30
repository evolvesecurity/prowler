from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class exchange_whitelisted_domains(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-ExchangeOnline -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        result = provider.session.execute("Get-TransportRule | Where-Object { ($_.SetScl -eq -1 -and $_.SenderDomainIs -ne $null) } | Select-Object Name, SenderDomainIs | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                rules = json.loads(result)
            except Exception as e:
                rules = []
        else:
            rules = result if result else []
        if not rules:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"WhitelistedDomains": []},
                resource_name="WhitelistedDomains",
                resource_id="WhitelistedDomains",
                resource_location="global",
            )
            report.status = "PASS"
            report.status_extended = "No transport rules with whitelisted domains found."
            findings.append(report)
        else:
            if isinstance(rules, dict):
                rules = [rules]
            for rule in rules:
                name = rule.get('Name', 'Unknown')
                sender_domain_is = rule.get('SenderDomainIs', None)
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={"Name": name, "SenderDomainIs": sender_domain_is},
                    resource_name=name,
                    resource_id=name,
                    resource_location="global",
                )
                report.status = "FAIL"
                report.status_extended = f"Transport rule '{name}' has whitelisted domains: {sender_domain_is}."
                findings.append(report)
        return findings
