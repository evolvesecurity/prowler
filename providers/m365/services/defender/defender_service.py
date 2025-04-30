from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Defender(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.powershell.connect_exchange_online()
        self.malware_policies = self._get_malware_filter_policy()
        self.safelinks_policies = self._get_safelinks_policy()
        self.powershell.close()

    def _get_malware_filter_policy(self):
        logger.info("M365 - Getting Defender malware filter policy...")
        malware_policies = []
        try:
            malware_policy = self.powershell.get_malware_filter_policy()
            if isinstance(malware_policy, dict):
                malware_policy = [malware_policy]
            for policy in malware_policy:
                malware_policies.append(
                    DefenderMalwarePolicy(
                        enable_file_filter=policy.get("EnableFileFilter", True),
                        identity=policy.get("Identity", ""),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return malware_policies

    def _get_safelinks_policy(self):
        logger.info("M365 - Getting Defender SafeLinks policies...")
        safelinks_policies = []
        try:
            policies = self.powershell.get_safelinks_policy()
            if isinstance(policies, dict):
                policies = [policies]
            for policy in policies:
                safelinks_policies.append(
                    DefenderSafeLinksPolicy(
                        Name=policy.get("Name", ""),
                        EnableSafeLinksForEmail=policy.get("EnableSafeLinksForEmail", False),
                        EnableSafeLinksForTeams=policy.get("EnableSafeLinksForTeams", False),
                        EnableSafeLinksForOffice=policy.get("EnableSafeLinksForOffice", False),
                        TrackClicks=policy.get("TrackClicks", False),
                        AllowClickThrough=policy.get("AllowClickThrough", False),
                        ScanUrls=policy.get("ScanUrls", False),
                        EnableForInternalSenders=policy.get("EnableForInternalSenders", False),
                        DeliverMessageAfterScan=policy.get("DeliverMessageAfterScan", False),
                        DisableUrlRewrite=policy.get("DisableUrlRewrite", False),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return safelinks_policies


class DefenderMalwarePolicy(BaseModel):
    enable_file_filter: bool
    identity: str

class DefenderSafeLinksPolicy(BaseModel):
    Name: str
    EnableSafeLinksForEmail: bool
    EnableSafeLinksForTeams: bool
    EnableSafeLinksForOffice: bool
    TrackClicks: bool
    AllowClickThrough: bool
    ScanUrls: bool
    EnableForInternalSenders: bool
    DeliverMessageAfterScan: bool
    DisableUrlRewrite: bool
