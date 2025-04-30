from typing import Optional
import sys
import os
from datetime import datetime

from prowler.lib.powershell.powershell import PowerShellSession
from prowler.providers.common.provider import Provider
from prowler.providers.m365.models import M365OutputOptions, M365Mutelist


class M365Provider(Provider):
    """
    M365 Provider class for handling Microsoft 365 authentication and services.
    Supports certificate-based authentication for various M365 services.
    """

    REQUIRED_MODULES = [
        "Microsoft.Graph.Authentication",
        "MicrosoftTeams",
        "ExchangeOnlineManagement",
        "Microsoft.PowerShell.SecretManagement"
    ]

    def __init__(
        self,
        certificate_thumbprint: str,
        application_id: str,
        tenant_id: str,
        organization: Optional[str] = None,
        output_options: Optional[M365OutputOptions] = None,
        mutelist_file_path: Optional[str] = None,
    ):
        """
        Initialize M365 provider with certificate authentication.

        Args:
            certificate_thumbprint (str): The thumbprint of the certificate to use for authentication
            application_id (str): The application ID (client ID) for the service principal
            tenant_id (str): The tenant ID for the M365 organization
            organization (str, optional): The organization domain for Exchange Online and IPPS
            output_options (M365OutputOptions, optional): Output options for the provider
            mutelist_file_path (str, optional): Path to the mutelist file
        """
        super().__init__()
        self.type = "m365"  # Add provider type
        self.certificate_thumbprint = certificate_thumbprint
        self.application_id = application_id
        self.tenant_id = tenant_id
        self.organization = organization
        self.powershell = PowerShellSession()
        self.connected_services = {
            "teams": False,
            "graph": False,
            "exchange": False,
            "ipps": False,
        }
        self.output_options = output_options
        self.mutelist = M365Mutelist(mutelist_file_path=mutelist_file_path)
        self._validate_required_modules()
        self._validate_certificate()

    def _validate_required_modules(self) -> None:
        """Validate that all required PowerShell modules are installed."""
        # Check each required module
        for module in self.REQUIRED_MODULES:
            # Try to get the module from the current session
            command = f"Get-Module -Name {module} -ErrorAction SilentlyContinue | Select-Object Name, Version, Path"
            result = self.powershell.execute(command)
            
            if not result:
                # If not found in session, try to find it in the module paths
                command = f"Get-Module -ListAvailable -Name {module} -ErrorAction SilentlyContinue | Select-Object Name, Version, Path"
                result = self.powershell.execute(command)
                
                if result:
                    command = f"Import-Module {module} -Force -ErrorAction SilentlyContinue; Get-Module -Name {module} | Select-Object Name, Version, Path"
                    result = self.powershell.execute(command)
            
            if not result:
                raise ImportError(
                    f"Required PowerShell module {module} is not installed or cannot be loaded. "
                    f"Please try installing it manually using: Install-Module -Name {module} -Force -AllowClobber -Scope CurrentUser"
                )

    def _validate_certificate(self) -> None:
        """Validate that the certificate exists and is valid."""
        # First, try to get the certificate directly
        command = f"""
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {{ $_.Thumbprint -eq '{self.certificate_thumbprint}' }}
        if ($cert) {{
            $certDetails = @{{
                Subject = $cert.Subject
                NotBefore = $cert.NotBefore.ToString("yyyy-MM-ddTHH:mm:ss")
                NotAfter = $cert.NotAfter.ToString("yyyy-MM-ddTHH:mm:ss")
                HasPrivateKey = $cert.HasPrivateKey
                PrivateKey = if ($cert.PrivateKey) {{ "Present" }} else {{ "Not Present" }}
                Exportable = $cert.PrivateKey.CspKeyContainerInfo.Exportable
            }}
            $certDetails | ConvertTo-Json
        }}
        """
        result = self.powershell.execute(command)
        
        if not result:
            raise ValueError(f"Certificate with thumbprint {self.certificate_thumbprint} not found in the certificate store")

    def connect_teams(self) -> bool:
        """Connect to Microsoft Teams using certificate authentication."""
        if not self.connected_services["teams"]:
            command = (
                f"Connect-MicrosoftTeams -CertificateThumbprint '{self.certificate_thumbprint}' "
                f"-ApplicationId '{self.application_id}' -TenantId '{self.tenant_id}'"
            )
            result = self.powershell.execute(command)
            if not result:
                raise ConnectionError("Failed to connect to Microsoft Teams")
            self.connected_services["teams"] = True
            return True
        return True

    def connect_graph(self) -> bool:
        """Connect to Microsoft Graph using certificate authentication."""
        if not self.connected_services["graph"]:
            command = (
                f"Connect-MgGraph -CertificateThumbprint '{self.certificate_thumbprint}' "
                f"-ClientId '{self.application_id}' -TenantId '{self.tenant_id}' -NoWelcome"
            )
            result = self.powershell.execute(command)
            if not result:
                raise ConnectionError("Failed to connect to Microsoft Graph")
            self.connected_services["graph"] = True
            return True
        return True

    def connect_exchange(self) -> bool:
        """Connect to Exchange Online using certificate authentication."""
        if not self.connected_services["exchange"]:
            if not self.organization:
                raise ValueError("Organization domain is required for Exchange Online connection")
            command = (
                f"Connect-ExchangeOnline -CertificateThumbprint '{self.certificate_thumbprint}' "
                f"-AppId '{self.application_id}' -Organization '{self.organization}'"
            )
            result = self.powershell.execute(command)
            if not result:
                raise ConnectionError("Failed to connect to Exchange Online")
            self.connected_services["exchange"] = True
            return True
        return True

    def connect_ipps(self) -> bool:
        """Connect to IPPS (Information Protection and Privacy) using certificate authentication."""
        if not self.connected_services["ipps"]:
            if not self.organization:
                raise ValueError("Organization domain is required for IPPS connection")
            command = (
                f"Connect-IPPSSession -CertificateThumbprint '{self.certificate_thumbprint}' "
                f"-AppId '{self.application_id}' -Organization '{self.organization}'"
            )
            result = self.powershell.execute(command)
            if not result:
                raise ConnectionError("Failed to connect to IPPS")
            self.connected_services["ipps"] = True
            return True
        return True

    def disconnect_all(self) -> None:
        """Disconnect from all connected M365 services."""
        for service, connected in self.connected_services.items():
            if connected:
                try:
                    command = f"Disconnect-{service.title()}"
                    self.powershell.execute(command)
                except Exception as e:
                    print(f"Warning: Failed to disconnect from {service}: {str(e)}")
                finally:
                    self.connected_services[service] = False
        self.powershell.close()

    def print_credentials(self) -> None:
        """Print the current authentication configuration."""
        print("\nM365 Provider configured with:")
        print(f"Certificate Thumbprint: {self.certificate_thumbprint}")
        print(f"Application ID: {self.application_id}")
        print(f"Tenant ID: {self.tenant_id}")
        if self.organization:
            print(f"Organization: {self.organization}")

    def get_checks_to_execute_by_audit_resources(self) -> dict:
        """
        Get the checks to execute based on audit resources.
        
        Returns:
            dict: A dictionary mapping resource types to their checks
        """
        # Define the available resources and their checks
        resources = {
            "m365": {
                "checks": [
                    "m365_teams_external_sharing_disabled",
                    "m365_teams_guest_access_disabled",
                    "m365_teams_private_channel_creation_disabled",
                    "m365_teams_anonymous_join_disabled",
                    "m365_teams_meeting_recording_disabled",
                    "m365_teams_screen_sharing_disabled",
                    "m365_teams_file_sharing_disabled",
                    "m365_teams_chat_disabled",
                    "m365_teams_meeting_disabled",
                    "m365_teams_calling_disabled",
                    "m365_teams_live_events_disabled",
                    "m365_teams_private_channel_disabled",
                    "m365_teams_guest_access_disabled",
                    "m365_teams_external_sharing_disabled",
                    "m365_teams_anonymous_join_disabled",
                    "m365_teams_meeting_recording_disabled",
                    "m365_teams_screen_sharing_disabled",
                    "m365_teams_file_sharing_disabled",
                    "m365_teams_chat_disabled",
                    "m365_teams_meeting_disabled",
                    "m365_teams_calling_disabled",
                    "m365_teams_live_events_disabled"
                ]
            }
        }
        
        return resources

    @property
    def identity(self):
        class IdentityObj:
            def __init__(self, data, tenant_domain):
                self.__dict__.update(data)
                self.tenant_domain = tenant_domain

        tenant_domain = self.organization if self.organization else "Unknown tenant domain (missing AAD permissions)"
        try:
            # First, try to get the current user from Microsoft Graph
            command = """
            $graph = Connect-MgGraph -CertificateThumbprint '{thumbprint}' -ClientId '{app_id}' -TenantId '{tenant_id}' -NoWelcome
            $me = Get-MgUser -UserId (Get-MgContext).Account
            @{{
                id = $me.Id
                displayName = $me.DisplayName
                userPrincipalName = $me.UserPrincipalName
                accountType = "User"
            }} | ConvertTo-Json
            """.format(
                thumbprint=self.certificate_thumbprint,
                app_id=self.application_id,
                tenant_id=self.tenant_id
            )
            result = self.powershell.execute(command)
            if result:
                return IdentityObj({
                    "id": result.get("id", ""),
                    "display_name": result.get("displayName", ""),
                    "user_principal_name": result.get("userPrincipalName", ""),
                    "account_type": result.get("accountType", "User")
                }, tenant_domain)
            # If that fails, try to get the service principal information
            command = """
            $graph = Connect-MgGraph -CertificateThumbprint '{thumbprint}' -ClientId '{app_id}' -TenantId '{tenant_id}' -NoWelcome
            $sp = Get-MgServicePrincipal -ServicePrincipalId '{app_id}'
            @{{
                id = $sp.Id
                displayName = $sp.DisplayName
                appId = $sp.AppId
                accountType = "ServicePrincipal"
            }} | ConvertTo-Json
            """.format(
                thumbprint=self.certificate_thumbprint,
                app_id=self.application_id,
                tenant_id=self.tenant_id
            )
            result = self.powershell.execute(command)
            if result:
                return IdentityObj({
                    "id": result.get("id", ""),
                    "display_name": result.get("displayName", ""),
                    "app_id": result.get("appId", ""),
                    "account_type": result.get("accountType", "ServicePrincipal")
                }, tenant_domain)
            # If both fail, return basic information
            return IdentityObj({
                "id": self.application_id,
                "display_name": "Service Principal",
                "app_id": self.application_id,
                "account_type": "ServicePrincipal"
            }, tenant_domain)
        except Exception as e:
            print(f"Warning: Could not get detailed identity information: {str(e)}")
            # Return basic information if detailed lookup fails
            return IdentityObj({
                "id": self.application_id,
                "display_name": "Service Principal",
                "app_id": self.application_id,
                "account_type": "ServicePrincipal"
            }, tenant_domain) 