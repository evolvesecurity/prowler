from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.admincenter.admincenter_service import AdminCenter

def get_admincenter_client():
    provider = Provider.get_global_provider()
    return AdminCenter(provider)
