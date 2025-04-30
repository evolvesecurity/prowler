from dataclasses import dataclass
from typing import List, Optional, Any


@dataclass
class M365Mutelist:
    """Mutelist for M365 provider."""
    
    mutelist_file_path: Optional[str] = None
    mutelist: List[str] = None

    def __post_init__(self):
        if self.mutelist is None:
            self.mutelist = []


@dataclass
class M365Credentials:
    user: str = ""
    passwd: str = ""
    client_id: str = ""
    client_secret: str = ""
    tenant_id: str = ""
    certificate_thumbprint: str = ""
    organization: str = ""
    auth_method: str = ""  # One of: 'env', 'sp_env', 'azcli', 'browser', 'cert', ''


@dataclass
class M365IdentityInfo:
    tenant_id: str = ""
    tenant_domain: str = ""
    identity_id: str = ""
    identity_type: str = ""


@dataclass
class M365OutputOptions:
    """Output options for M365 provider."""

    output_formats: List[str]
    output_directory: str = "."
    output_filename: Optional[str] = None
    security_hub: bool = False
    quiet: bool = False
    only_fails: bool = False
    output_modes: Optional[List[str]] = None
    only_logs: bool = False
    fixer: Optional[str] = None
    identity: Optional[M365IdentityInfo] = None

    def __post_init__(self):
        if self.output_modes is None or not self.output_modes:
            self.output_modes = self.output_formats.copy() if self.output_formats else []
        if not self.output_filename:
            domain = getattr(self.identity, 'tenant_domain', None) if self.identity else None
            tid = getattr(self.identity, 'tenant_id', None) if self.identity else None
            from prowler.config.config import output_file_timestamp
            base = domain if domain and domain != 'N/A' else (tid if tid and tid != 'N/A' else 'unknown')
            self.output_filename = f"prowler-output-{base}-{output_file_timestamp}"


@dataclass
class M365RegionConfig:
    name: str = ""
    authority: Any = None
    base_url: str = ""
    credential_scopes: List[str] = None 