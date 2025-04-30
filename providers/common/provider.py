"""Base class for all providers."""
from abc import ABC, abstractmethod


class Provider(ABC):
    """Abstract base class for all cloud providers."""

    _global_provider = None

    @classmethod
    def init_global_provider(cls, args):
        """Initialize the global provider instance based on command line arguments."""
        if args.provider == "m365":
            # Import here to avoid circular import
            from prowler.providers.m365.m365_provider import M365Provider
            if args.cert_auth:
                cls._global_provider = M365Provider(
                    sp_env_auth=False,
                    env_auth=False,
                    az_cli_auth=False,
                    browser_auth=False,
                    # Map CLI args to expected provider args
                    tenant_id=args.tenant_id,
                    client_id=args.app_id,  # Map --app-id to client_id
                    certificate_thumbprint=args.cert_thumbprint,  # Map --cert-thumbprint to certificate_thumbprint
                    organization=args.organization,  # Pass organization correctly
                    region="M365Global",
                )
            else:
                raise ValueError("Certificate authentication (--cert-auth) is required for M365 provider")

    @classmethod
    def get_global_provider(cls):
        """Get the global provider instance."""
        return cls._global_provider

    @abstractmethod
    def print_credentials(self) -> None:
        """Print the current authentication configuration."""
        pass 