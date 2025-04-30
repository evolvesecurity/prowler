from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.defender.defender_service import Defender

def get_defender_client():
    provider = Provider.get_global_provider()
    return Defender(provider)
