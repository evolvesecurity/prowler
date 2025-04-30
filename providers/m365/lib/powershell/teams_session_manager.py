# prowler/providers/m365/lib/powershell/teams_session_manager.py
# Singleton Teams PowerShell session manager for persistent Teams connection across all checks

class TeamsSessionManager:
    _instance = None

    def __init__(self, provider):
        self.provider = provider
        self.session = provider.session
        self._initialized = False

    @classmethod
    def get_instance(cls, provider):
        if cls._instance is None:
            cls._instance = TeamsSessionManager(provider)
        return cls._instance

    def initialize(self):
        if not self._initialized:
            self.session.execute("Import-Module MicrosoftTeams -ErrorAction SilentlyContinue")
            # Add Teams connection logic here (Connect-MicrosoftTeams ...)
            from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
            teams_auth_args = M365PowerShell.get_microsoft_teams_auth_args(self.provider._credentials)
            connect_cmd = (
                f"Connect-MicrosoftTeams {teams_auth_args} "
                f"-CertificateThumbprint '{self.provider.certificate_thumbprint}' "
                f"-TenantId '{self.provider.tenant_id}'"
            )
            connect_output = self.session.execute(connect_cmd)
            # Optionally: import session for legacy cmdlets
            session_cmd = "$session = Get-CsOnlineSession; if ($session) { Import-PSSession $session -AllowClobber }"
            session_output = self.session.execute(session_cmd)
            self._initialized = True

    def run(self, command):
        return self.session.execute(command)
