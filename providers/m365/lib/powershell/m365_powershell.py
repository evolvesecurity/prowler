import msal

from prowler.lib.powershell.powershell import PowerShellSession
from prowler.providers.m365.models import M365Credentials


class M365PowerShell(PowerShellSession):
    @staticmethod
    def get_mg_graph_auth_args(credentials: M365Credentials) -> str:
        """
        Returns the correct argument string for Connect-MgGraph based on the authentication method.
        Supported methods: --env-auth, --sp-env-auth, --az-cli-auth, --browser-auth, --cert-auth
        """
        auth_method = getattr(credentials, 'auth_method', None)
        if auth_method == "azcli":
            return "-Identity -NoWelcome"
        if auth_method == "browser":
            tenant_id = getattr(credentials, 'tenant_id', '')
            return f"-Scopes 'User.Read.All' -TenantId '{tenant_id}' -NoWelcome" if tenant_id else "-Scopes 'User.Read.All' -NoWelcome"
        if auth_method == "sp_env" or auth_method == "env":
            # Use service principal credentials from env vars
            return (
                f"-ClientId '{credentials.client_id}' -TenantId '{credentials.tenant_id}' -ClientSecret (ConvertTo-SecureString '{credentials.client_secret}' -AsPlainText -Force) -NoWelcome"
            )
        if getattr(credentials, 'certificate_thumbprint', None) or auth_method == "cert":
            return (
                f"-CertificateThumbprint '{credentials.certificate_thumbprint}' "
                f"-ClientId '{credentials.client_id}' -TenantId '{credentials.tenant_id}' -NoWelcome"
            )
        # Default fallback to credential
        return "-Credential $credential -NoWelcome"

    @staticmethod
    def get_exchange_online_auth_args(credentials: M365Credentials) -> str:
        """
        Returns the correct argument string for Connect-ExchangeOnline based on the authentication method.
        Supported methods: --env-auth, --sp-env-auth, --az-cli-auth, --browser-auth, --cert-auth
        """
        auth_method = getattr(credentials, 'auth_method', None)
        if auth_method == "azcli":
            return "-UserPrincipalName (az account show --query user.name -o tsv)"
        if auth_method == "browser":
            tenant_id = getattr(credentials, 'tenant_id', '')
            return f"-UserPrincipalName (Read-Host 'Enter UPN') -ShowProgress $false -Organization '{tenant_id}'" if tenant_id else "-UserPrincipalName (Read-Host 'Enter UPN') -ShowProgress $false"
        if auth_method == "sp_env" or auth_method == "env":
            return (
                f"-AppId '{credentials.client_id}' -Organization '{credentials.organization}' -CertificateThumbprint '{credentials.certificate_thumbprint}'"
            )
        if getattr(credentials, 'certificate_thumbprint', None) or auth_method == "cert":
            return (
                f"-CertificateThumbprint '{credentials.certificate_thumbprint}' "
                f"-AppId '{credentials.client_id}' -Organization '{credentials.organization}'"
            )
        return "-Credential $credential"

    @staticmethod
    def get_microsoft_teams_auth_args(credentials: M365Credentials) -> str:
        """
        Returns the correct argument string for Connect-MicrosoftTeams based on the authentication method.
        Supported methods: --env-auth, --sp-env-auth, --az-cli-auth, --browser-auth, --cert-auth
        """
        auth_method = getattr(credentials, 'auth_method', None)
        if auth_method == "azcli":
            return "-Identity"
        if auth_method == "browser":
            tenant_id = getattr(credentials, 'tenant_id', '')
            return f"-TenantId '{tenant_id}'" if tenant_id else ""
        if auth_method == "sp_env" or auth_method == "env":
            return (
                f"-ApplicationId '{credentials.client_id}' -TenantId '{credentials.tenant_id}' -CertificateThumbprint '{credentials.certificate_thumbprint}'"
            )
        if getattr(credentials, 'certificate_thumbprint', None) or auth_method == "cert":
            return (
                f"-CertificateThumbprint '{credentials.certificate_thumbprint}' "
                f"-ApplicationId '{credentials.client_id}' -TenantId '{credentials.tenant_id}'"
            )
        return "-Credential $credential"

    @staticmethod
    def get_ipps_session_auth_args(credentials: M365Credentials) -> str:
        """
        Returns the correct argument string for Connect-IPPSSession based on the authentication method.
        Supported methods: --env-auth, --sp-env-auth, --az-cli-auth, --browser-auth, --cert-auth
        """
        auth_method = getattr(credentials, 'auth_method', None)
        if auth_method == "azcli":
            return "-Identity"
        if auth_method == "browser":
            tenant_id = getattr(credentials, 'tenant_id', '')
            return f"-UserPrincipalName (Read-Host 'Enter UPN') -Organization '{tenant_id}'" if tenant_id else "-UserPrincipalName (Read-Host 'Enter UPN')"
        if auth_method == "sp_env" or auth_method == "env":
            return (
                f"-AppId '{credentials.client_id}' -Organization '{credentials.organization}' -CertificateThumbprint '{credentials.certificate_thumbprint}'"
            )
        if getattr(credentials, 'certificate_thumbprint', None) or auth_method == "cert":
            return (
                f"-CertificateThumbprint '{credentials.certificate_thumbprint}' "
                f"-AppId '{credentials.client_id}' -Organization '{credentials.organization}'"
            )
        return "-Credential $credential"

    """
    Microsoft 365 specific PowerShell session management implementation.

    This class extends the base PowerShellSession to provide Microsoft 365 specific
    functionality, including authentication, Teams management, and Exchange Online
    operations.

    Features:
    - Microsoft 365 credential management
    - Teams client configuration
    - Exchange Online connectivity
    - Audit log configuration
    - Secure credential handling

    Attributes:
        credentials (M365Credentials): The Microsoft 365 credentials used for authentication.

    Note:
        This class requires the Microsoft Teams and Exchange Online PowerShell modules
        to be installed and available in the PowerShell environment.
    """

    def __init__(self, credentials: M365Credentials):
        """
        Initialize a Microsoft 365 PowerShell session.

        Sets up the PowerShell session and initializes the provided credentials
        for Microsoft 365 authentication.

        Args:
            credentials (M365Credentials): The Microsoft 365 credentials to use
                for authentication.
        """
        super().__init__()
        self.init_credential(credentials)

    def init_credential(self, credentials: M365Credentials) -> None:
        """
        Initialize PowerShell credential object for Microsoft 365 authentication.

        Sanitizes the username and password, then creates a PSCredential object
        in the PowerShell session for use with Microsoft 365 cmdlets.

        Args:
            credentials (M365Credentials): The credentials object containing
                username and password.

        Note:
            The credentials are sanitized to prevent command injection and
            stored securely in the PowerShell session.
        """
        # Defensive: If credentials is None, do nothing (should not happen, but prevents crash)
        if credentials is None:
            self.certificate_thumbprint = None
            self.app_id = None
            self.tenant_id = None
            self.organization = None
            return

        self.certificate_thumbprint = getattr(credentials, 'certificate_thumbprint', None)
        self.app_id = getattr(credentials, 'client_id', None)
        self.tenant_id = getattr(credentials, 'tenant_id', None)
        self.organization = getattr(credentials, 'organization', None)
        if self.certificate_thumbprint:
            # No need to create $credential for cert-based auth
            return
        # Username/password fallback
        user = self.sanitize(credentials.user)
        passwd = self.sanitize(credentials.passwd)
        self.execute(f'$user = "{user}"')
        self.execute(f'$secureString = "{passwd}" | ConvertTo-SecureString')
        self.execute(
            "$credential = New-Object System.Management.Automation.PSCredential ($user, $secureString)"
        )

    def test_credentials(self, credentials: M365Credentials) -> bool:
        """
        Test Microsoft 365 credentials by attempting to authenticate against Entra ID.

        Args:
            credentials (M365Credentials): The credentials object containing
                username and password to test.

        Returns:
            bool: True if credentials are valid and authentication succeeds, False otherwise.
        """
        self.execute(
            f'$securePassword = "{credentials.passwd}" | ConvertTo-SecureString\n'
        )
        self.execute(
            f'$credential = New-Object System.Management.Automation.PSCredential("{credentials.user}", $securePassword)\n'
        )
        self.process.stdin.write(
            'Write-Output "$($credential.GetNetworkCredential().Password)"\n'
        )
        self.process.stdin.write(f"Write-Output '{self.END}'\n")
        decrypted_password = self.read_output()

        app = msal.ConfidentialClientApplication(
            client_id=credentials.client_id,
            client_credential=credentials.client_secret,
            authority=f"https://login.microsoftonline.com/{credentials.tenant_id}",
        )

        result = app.acquire_token_by_username_password(
            username=credentials.user,
            password=decrypted_password,  # Needs to be in plain text
            scopes=["https://graph.microsoft.com/.default"],
        )

        return "access_token" in result

    def connect_microsoft_teams(self) -> dict:
        """
        Connect to Microsoft Teams Module PowerShell Module.

        Establishes a connection to Microsoft Teams using the initialized credentials.

        Returns:
            dict: Connection status information in JSON format.

        Note:
            This method requires the Microsoft Teams PowerShell module to be installed.
        """
        if self.certificate_thumbprint:
            return self.execute(
                f'Connect-MicrosoftTeams -CertificateThumbprint "{self.certificate_thumbprint}" '
                f'-ApplicationId "{self.app_id}" -TenantId "{self.tenant_id}"'
            )
        return self.execute("Connect-MicrosoftTeams -Credential $credential")

    def get_teams_settings(self) -> dict:
        """
        Get Teams Client Settings.

        Retrieves the current Microsoft Teams client configuration settings.

        Returns:
            dict: Teams client configuration settings in JSON format.

        Example:
            >>> get_teams_settings()
            {
                "AllowBox": true,
                "AllowDropBox": true,
                "AllowGoogleDrive": true
            }
        """
        return self.execute("Get-CsTeamsClientConfiguration | ConvertTo-Json")

    def connect_exchange_online(self) -> dict:
        """
        Connect to Exchange Online PowerShell Module.

        Establishes a connection to Exchange Online using the initialized credentials.

        Returns:
            dict: Connection status information in JSON format.

        Note:
            This method requires the Exchange Online PowerShell module to be installed.
        """
        if self.certificate_thumbprint:
            return self.execute(
                f'Connect-ExchangeOnline -CertificateThumbprint "{self.certificate_thumbprint}" '
                f'-AppId "{self.app_id}" -Organization "{self.organization}"'
            )
        return self.execute("Connect-ExchangeOnline -Credential $credential")

    def get_audit_log_config(self) -> dict:
        """
        Get Purview Admin Audit Log Settings.

        Retrieves the current audit log configuration settings for Microsoft Purview.

        Returns:
            dict: Audit log configuration settings in JSON format.

        Example:
            >>> get_audit_log_config()
            {
                "UnifiedAuditLogIngestionEnabled": true
            }
        """
        return self.execute(
            "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled | ConvertTo-Json"
        )

    def get_malware_filter_policy(self) -> dict:
        """
        Get Defender Malware Filter Policy.

        Retrieves the current Defender anti-malware filter policy settings.

        Returns:
            dict: Malware filter policy settings in JSON format.

        Example:
            >>> get_malware_filter_policy()
            {
                "EnableFileFilter": true,
                "Identity": "Default"
            }
        """
        return self.execute("Get-MalwareFilterPolicy | ConvertTo-Json")

    def get_organization_config(self) -> dict:
        """
        Get Exchange Online Organization Configuration.

        Retrieves the current Exchange Online organization configuration settings.

        Returns:
            dict: Organization configuration settings in JSON format.

        Example:
            >>> get_organization_config()
            {
                "Name": "MyOrganization",
                "Guid": "12345678-1234-1234-1234-123456789012"
                "AuditDisabled": false
            }
        """
        return self.execute("Get-OrganizationConfig | ConvertTo-Json")

    def get_mailbox_audit_config(self) -> dict:
        """
        Get Exchange Online Mailbox Audit Configuration.

        Retrieves the current mailbox audit configuration settings for Exchange Online.

        Returns:
            dict: Mailbox audit configuration settings in JSON format.

        Example:
            >>> get_mailbox_audit_config()
            {
                "Name": "MyMailbox",
                "Id": "12345678-1234-1234-1234-123456789012",
                "AuditBypassEnabled": false
            }
        """
        return self.execute("Get-MailboxAuditBypassAssociation | ConvertTo-Json")

    def get_safelinks_policy(self) -> dict:
        """
        Get SafeLinks Policy.

        Retrieves the current SafeLinks policy settings.

        Returns:
            dict: SafeLinks policy settings in JSON format.

        Example:
            >>> get_safelinks_policy()
            [
                {
                    "Name": "Default",
                    "EnableSafeLinksForEmail": true,
                    ...
                }
            ]
        """
        return self.execute("Get-SafeLinksPolicy | ConvertTo-Json")

    def connect_mg_graph(self) -> dict:
        if self.certificate_thumbprint:
            return self.execute(
                f'Connect-MgGraph -CertificateThumbprint "{self.certificate_thumbprint}" '
                f'-ClientId "{self.app_id}" -TenantId "{self.tenant_id}" -NoWelcome'
            )
        return self.execute("Connect-MgGraph -Credential $credential -NoWelcome")

    def connect_ipps_session(self) -> dict:
        if self.certificate_thumbprint:
            return self.execute(
                f'Connect-IPPSSession -CertificateThumbprint "{self.certificate_thumbprint}" '
                f'-AppId "{self.app_id}" -Organization "{self.organization}"'
            )
        return self.execute("Connect-IPPSSession -Credential $credential")
