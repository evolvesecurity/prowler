from typing import List
from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
import json

class defender_comprehensive_attachment_filtering(Check):
    def execute(self) -> List[CheckReportM365]:
        findings = []
        provider = Provider.get_global_provider()
        provider.session.execute("Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue")
        exo_auth_args = M365PowerShell.get_exchange_online_auth_args(provider._credentials)
        connect_cmd = (
            f"Connect-ExchangeOnline {exo_auth_args} "
            f"-AppId '{provider.client_id}' -Organization '{provider.organization}'"
        )
        provider.session.execute(connect_cmd)
        l2_extensions = [
            "7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller", "applescript", "application", "appref-ms", "appx", "appxbundle", "arj", "asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com", "cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb", "desktopthemepackfile", "dex", "diagcab", "dif", "dir", "dll", "dmg", "doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz", "hlp", "hta", "htc", "htm", "html", "hwpx", "ics", "img", "inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse", "kext", "ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi", "msix", "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd", "pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt", "pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "pub", "py", "pyc", "pyo", "pyw", "pyz", "pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct", "searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs", "shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys", "tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe", "vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc", "wsf", "wsh", "xla", "xlam", "xlc", "xll", "xlm", "xls", "xlsb", "xlsm", "xlt", "xltm", "xlw", "xnk", "xps", "xsl", "xz", "z"
        ]
        result = provider.session.execute("Get-MalwareFilterPolicy | ConvertTo-Json")
        if isinstance(result, str):
            try:
                policies = json.loads(result)
                if isinstance(policies, dict):
                    policies = [policies]
            except Exception as e:
                policies = []
        elif isinstance(result, list):
            policies = result
        elif isinstance(result, dict):
            policies = [result]
        else:
            policies = []
        extension_policies = [p for p in policies if p.get("FileTypes") and isinstance(p["FileTypes"], list) and len(p["FileTypes"]) > 50]
        if not extension_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Comprehensive Attachment Filtering",
                resource_id="ComprehensiveAttachmentFiltering",
                resource_location="global",
            )
            report.status = "FAIL"
            report.status_extended = "No malware filter policies with over 50 extensions were found."
            findings.append(report)
            return findings
        missing_extensions_overall = set()
        for policy in extension_policies:
            missing_extensions = [ext for ext in l2_extensions if ext not in policy.get("FileTypes", [])]
            if missing_extensions:
                missing_extensions_overall.update(missing_extensions)
                status = "FAIL"
                status_extended = f"Missing extensions for policy '{policy.get('Identity', 'Unknown')}': {', '.join(missing_extensions)}"
            else:
                status = "PASS"
                status_extended = f"Policy '{policy.get('Identity', 'Unknown')}' contains all required extensions."
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.get("Identity", "Unknown"),
                resource_id=policy.get("Identity", "Unknown"),
                resource_location="global",
            )
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        if missing_extensions_overall:
            return findings
