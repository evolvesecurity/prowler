from typing import List
from prowler.lib.check.models import Check, CheckReportM365

class admincenter_sway_sharing(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Sway Sharing",
            resource_id="SwaySharing",
            resource_location="global",
        )
        report.status = "MANUAL"
        report.status_extended = (
            "Manual check required: Verify that Sway sharing is not allowed. "
            "Ensure 'Let people in the organization share their sways' is NOT checked. "
            "See: https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/Sway"
        )
        findings.append(report)
        return findings
