from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
import json

class entra_mfa_status_admin_roles(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue")
        connect_cmd = (
            f"Connect-MgGraph -CertificateThumbprint '{provider.certificate_thumbprint}' "
            f"-ClientId '{provider.client_id}' -TenantId '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        # Simulate the PowerShell logic for retrieving secure scores (MFA status for admin roles)
        result = provider.session.execute("Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/security/secureScores' -Method GET | ConvertTo-Json -Depth 10")
        if isinstance(result, str):
            try:
                secure_scores = json.loads(result)
            except Exception as e:
                secure_scores = None
        else:
            secure_scores = result
        # If secure_scores is a list, flatten it
        if isinstance(secure_scores, list) and len(secure_scores) > 0 and isinstance(secure_scores[0], dict) and 'controlScores' in secure_scores[0]:
            controls = secure_scores[0]['controlScores']
        elif isinstance(secure_scores, dict) and 'controlScores' in secure_scores:
            controls = secure_scores['controlScores']
        else:
            controls = []
        if not controls:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"SecureScores": secure_scores},
                resource_name="SecureScores",
                resource_id="SecureScores",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No MFA status data found for admin roles."
            findings.append(report)
        else:
            for control in controls:
                control_name = control.get('controlName', 'Unknown')
                implementation_status = control.get('implementationStatus', '')
                score = control.get('score', 0)
                score_percent = control.get('scoreInPercentage', 0)
                status = "PASS"
                status_extended = f"MFA control '{control_name}' is compliant."
                # Heuristic: if implementationStatus or description indicates not compliant, or score is 0, mark as FAIL
                if (
                    (isinstance(implementation_status, str) and ("not compliant" in implementation_status.lower() or "not enabled" in implementation_status.lower() or "disabled" in implementation_status.lower()))
                    or score == 0
                    or score_percent == 0
                ):
                    status = "FAIL"
                    status_extended = f"MFA control '{control_name}' is NOT compliant. implementationStatus: {implementation_status}, score: {score}, scoreInPercentage: {score_percent}"
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={
                        "ControlName": control_name,
                        "ImplementationStatus": implementation_status,
                        "Score": score,
                        "ScoreInPercentage": score_percent
                    },
                    resource_name=control_name,
                    resource_id=control_name,
                    resource_location="global",
                )
                report.status = status
                report.status_extended = status_extended
                findings.append(report)
        return findings
