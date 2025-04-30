import asyncio
import os
import re
from argparse import ArgumentTypeError
from os import getenv
from uuid import UUID
import subprocess
import json

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import (
    ClientSecretCredential,
    CredentialUnavailableError,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
)
from colorama import Fore, Style
from msal import ConfidentialClientApplication
from msgraph import GraphServiceClient

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.m365.exceptions.exceptions import (
    M365ArgumentTypeValidationError,
    M365BrowserAuthNoFlagError,
    M365BrowserAuthNoTenantIDError,
    M365ClientAuthenticationError,
    M365ClientIdAndClientSecretNotBelongingToTenantIdError,
    M365ConfigCredentialsError,
    M365CredentialsUnavailableError,
    M365DefaultAzureCredentialError,
    M365EnvironmentUserCredentialsError,
    M365EnvironmentVariableError,
    M365GetTokenIdentityError,
    M365HTTPResponseError,
    M365InteractiveBrowserCredentialError,
    M365InvalidProviderIdError,
    M365MissingEnvironmentUserCredentialsError,
    M365NoAuthenticationMethodError,
    M365NotTenantIdButClientIdAndClientSecretError,
    M365NotValidClientIdError,
    M365NotValidClientSecretError,
    M365NotValidTenantIdError,
    M365SetUpRegionConfigError,
    M365SetUpSessionError,
    M365TenantIdAndClientIdNotBelongingToClientSecretError,
    M365TenantIdAndClientSecretNotBelongingToClientIdError,
)
from prowler.providers.m365.lib.mutelist.mutelist import M365Mutelist
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
from prowler.providers.m365.lib.regions.regions import get_regions_config
from prowler.providers.m365.models import (
    M365Credentials,
    M365IdentityInfo,
    M365RegionConfig,
)


class M365Provider(Provider):
    """
    Represents an M365 provider.

    This class provides functionality to interact with the M365 resources.
    It handles authentication, region configuration, and provides access to various properties and methods
    related to the M365 provider.

    Attributes:
        _type (str): The type of the provider, which is set to "m365".
        _session (DefaultM365Credential): The session object associated with the M365 provider.
        _identity (M365IdentityInfo): The identity information for the M365 provider.
        _audit_config (dict): The audit configuration for the M365 provider.
        _region_config (M365RegionConfig): The region configuration for the M365 provider.
        _mutelist (M365Mutelist): The mutelist object associated with the M365 provider.
        audit_metadata (Audit_Metadata): The audit metadata for the M365 provider.
        client_id (str): The M365 client ID.
        tenant_id (str): The M365 tenant ID.

    Methods:
        __init__ -> Initializes the M365 provider.
        identity(self): Returns the identity of the M365 provider.
        type(self): Returns the type of the M365 provider.
        session(self): Returns the session object associated with the M365 provider.
        region_config(self): Returns the region configuration for the M365 provider.
        audit_config(self): Returns the audit configuration for the M365 provider.
        fixer_config(self): Returns the fixer configuration.
        output_options(self, options: tuple): Sets the output options for the M365 provider.
        mutelist(self) -> M365Mutelist: Returns the mutelist object associated with the M365 provider.
        setup_region_config(cls, region): Sets up the region configuration for the M365 provider.
        print_credentials(self): Prints the M365 credentials information.
        setup_session(cls, az_cli_auth, app_env_auth, browser_auth, managed_identity_auth, tenant_id, region_config): Set up the M365 session with the specified authentication method.
        get_checks_to_execute_by_audit_resources(self): Stub for get_checks_to_execute_by_audit_resources to avoid AttributeError.
    """

    _type: str = "m365"
    _session: DefaultAzureCredential  # Must be used besides being named for Azure
    _identity: M365IdentityInfo
    _audit_config: dict
    _region_config: M365RegionConfig
    _mutelist: M365Mutelist
    _credentials: M365Credentials
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata
    client_id: str
    tenant_id: str
    certificate_thumbprint: str
    organization: str

    def __init__(
        self,
        sp_env_auth: bool,
        env_auth: bool,
        az_cli_auth: bool,
        browser_auth: bool,
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None,
        region: str = "M365Global",
        certificate_thumbprint: str = None,
        user: str = None,
        encrypted_password: str = None,
        config_content: dict = None,
        config_path: str = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        fixer_config: dict = {},
        organization: str = None,
        # Accept CLI aliases for compatibility
        app_id: str = None,
        cert_thumbprint: str = None,
    ):
        """
        Initializes the M365 provider.

        Args:
            sp_env_auth (bool): Service principal environment authentication flag.
            env_auth (bool): Environment authentication flag.
            az_cli_auth (bool): Azure CLI authentication flag.
            browser_auth (bool): Browser authentication flag.
            tenant_id (str): The M365 Active Directory tenant ID.
            client_id (str): The M365 client ID.
            client_secret (str): The M365 client secret.
            region (str): The M365 region.
            certificate_thumbprint (str): The certificate thumbprint.
            user (str): The M365 user.
            encrypted_password (str): The encrypted password.
            config_content (dict): The configuration content.
            config_path (str): The path to the configuration file.
            mutelist_path (str): The path to the mutelist file.
            mutelist_content (dict): The mutelist content.
            fixer_config (dict): The fixer configuration.
            organization (str): The organization.
            app_id (str): CLI alias for client_id.
            cert_thumbprint (str): CLI alias for certificate_thumbprint.
        """
        
        # Always use the alias if the main value is None
        self.client_id = client_id or app_id
        self.certificate_thumbprint = certificate_thumbprint or cert_thumbprint
        self.tenant_id = tenant_id
        self.organization = organization

        # Validate the authentication arguments
        self.validate_arguments(
            az_cli_auth,
            sp_env_auth,
            env_auth,
            browser_auth,
            self.tenant_id,
            self.client_id,
            client_secret,
            user,
            encrypted_password,
        )

        logger.info("Checking if region is different than default one")
        self._region_config = self.setup_region_config(region)

        # Get the dict from the static credentials
        m365_credentials = None
        if self.tenant_id and self.client_id and client_secret and user and encrypted_password:
            m365_credentials = self.validate_static_credentials(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=client_secret,
                user=user,
                encrypted_password=encrypted_password,
            )

        # Set up the M365 session
        self._session = self.setup_session(
            az_cli_auth,
            sp_env_auth,
            env_auth,
            browser_auth,
            self.tenant_id,
            m365_credentials,
            self._region_config,
            self.certificate_thumbprint,
            self.client_id,
            user,
        )


        # Set up PowerShell session credentials
        self._credentials = self.setup_powershell(
            env_auth,
            m365_credentials,
            az_cli_auth=az_cli_auth,
            sp_env_auth=sp_env_auth,
            browser_auth=browser_auth,
            cert_auth=bool(self.certificate_thumbprint),
        )

        # Set up the identity
        self._identity = self.setup_identity(
            az_cli_auth,
            sp_env_auth,
            env_auth,
            browser_auth,
            self.client_id,
        )

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist
        if mutelist_content:
            self._mutelist = M365Mutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = M365Mutelist(
                mutelist_path=mutelist_path,
            )

    @property
    def identity(self):
        """Returns the identity of the M365 provider."""
        return self._identity

    @property
    def type(self):
        """Returns the type of the M365 provider."""
        return self._type

    @property
    def session(self):
        """Returns the session object associated with the M365 provider."""
        return self._session

    @property
    def region_config(self):
        """Returns the region configuration for the M365 provider."""
        return self._region_config

    @property
    def audit_config(self):
        """Returns the audit configuration for the M365 provider."""
        return self._audit_config

    @property
    def fixer_config(self):
        """Returns the fixer configuration."""
        return self._fixer_config

    @property
    def mutelist(self) -> M365Mutelist:
        """Mutelist object associated with this M365 provider."""
        return self._mutelist

    @property
    def credentials(self) -> M365Credentials:
        """Return powershell credentials"""
        return self._credentials

    @staticmethod
    def validate_arguments(
        az_cli_auth: bool,
        sp_env_auth: bool,
        env_auth: bool,
        browser_auth: bool,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        user: str,
        encrypted_password: str,
    ):
        """
        Validates the authentication arguments for the M365 provider.

        Args:
            az_cli_auth (bool): Flag indicating whether Azure CLI authentication is enabled.
            sp_env_auth (bool): Flag indicating whether application authentication with environment variables is enabled.
            env_auth: (bool): Flag indicating whether to use application and PowerShell authentication with environment variables.
            browser_auth (bool): Flag indicating whether browser authentication is enabled.
            tenant_id (str): The M365 Tenant ID.
            client_id (str): The M365 Client ID.
            client_secret (str): The M365 Client Secret.
            user (str): The M365 User Account.
            encrpted_password (str): The M365 Encrypted Password.

        Raises:
            M365BrowserAuthNoTenantIDError: If browser authentication is enabled but the tenant ID is not found.
        """

        if not client_id and not client_secret and not user and not encrypted_password:
            if not browser_auth and tenant_id:
                raise M365BrowserAuthNoFlagError(
                    file=os.path.basename(__file__),
                    message="M365 tenant ID error: browser authentication flag (--browser-auth) not found",
                )
            elif (
                not az_cli_auth
                and not sp_env_auth
                and not browser_auth
                and not env_auth
            ):
                raise M365NoAuthenticationMethodError(
                    file=os.path.basename(__file__),
                    message="M365 provider requires at least one authentication method set: [--env-auth | --az-cli-auth | --sp-env-auth | --browser-auth]",
                )
            elif browser_auth and not tenant_id:
                raise M365BrowserAuthNoTenantIDError(
                    file=os.path.basename(__file__),
                    message="M365 Tenant ID (--tenant-id) is required for browser authentication mode",
                )
        else:
            if not tenant_id:
                raise M365NotTenantIdButClientIdAndClientSecretError(
                    file=os.path.basename(__file__),
                    message="Tenant Id is required for M365 static credentials. Make sure you are using the correct credentials.",
                )

    @staticmethod
    def setup_region_config(region):
        """
        Sets up the region configuration for the M365 provider.

        Args:
            region (str): The name of the region.

        Returns:
            M365RegionConfig: The region configuration object.

        """
        try:
            config = get_regions_config(region)

            return M365RegionConfig(
                name=region,
                authority=config["authority"],
                base_url=config["base_url"],
                credential_scopes=config["credential_scopes"],
            )
        except ArgumentTypeError as validation_error:
            logger.error(
                f"{validation_error.__class__.__name__}[{validation_error.__traceback__.tb_lineno}]: {validation_error}"
            )
            raise M365ArgumentTypeValidationError(
                file=os.path.basename(__file__),
                original_exception=validation_error,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise M365SetUpRegionConfigError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def setup_powershell(
        self,
        env_auth: bool,
        m365_credentials: dict = {},
        az_cli_auth: bool = False,
        sp_env_auth: bool = False,
        browser_auth: bool = False,
        cert_auth: bool = False,
    ):
        """
        Gets the M365 credentials and sets the correct auth_method for centralized auth.
        """
        auth_method = ""
        credentials = None
        if az_cli_auth:
            auth_method = "azcli"
        elif browser_auth:
            auth_method = "browser"
        elif sp_env_auth:
            auth_method = "sp_env"
        elif env_auth:
            auth_method = "env"
        elif cert_auth:
            auth_method = "cert"
        if env_auth:
            user = getenv("M365_USER", "")
            passwd = getenv("M365_PASSWORD", "")
            if not user or not passwd:
                raise M365MissingEnvironmentUserCredentialsError(
                    file=os.path.basename(__file__),
                    message="Missing M365_USER or M365_ENCRYPTED_PASSWORD environment variables required for credentials authentication."
                )
            client_id = getenv("M365_CLIENT_ID", "")
            client_secret = getenv("M365_CLIENT_SECRET", "")
            tenant_id = getenv("M365_TENANT_ID", "")
            certificate_thumbprint = getenv("M365_CERTIFICATE_THUMBPRINT", "")
            organization = getenv("M365_ORGANIZATION", "")
            credentials = M365Credentials(
                user=user,
                passwd=passwd,
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=tenant_id,
                certificate_thumbprint=certificate_thumbprint,
                organization=organization,
                auth_method=auth_method,
            )

        # Debug logging for credential values
        logger.debug(f"cert_auth={cert_auth}")
        logger.debug(f"client_id={self.client_id}")
        logger.debug(f"tenant_id={self.tenant_id}")
        logger.debug(f"certificate_thumbprint={self.certificate_thumbprint}")
        logger.debug(f"organization={self.organization}")

        # Certificate-based authentication via CLI args (centralized)
        if cert_auth:
            credentials = M365Credentials(
                client_id=self.client_id,
                tenant_id=self.tenant_id,
                certificate_thumbprint=self.certificate_thumbprint,
                organization=self.organization,
                auth_method=auth_method,
            )

        if credentials:
            # Only test credentials for username/password methods
            if auth_method in ("env", "sp_env"):
                test_session = M365PowerShell(credentials)
                try:
                    if test_session.test_credentials(credentials):
                        return credentials
                    raise M365EnvironmentUserCredentialsError(
                        file=os.path.basename(__file__),
                        message="M365_USER or M365_ENCRYPTED_PASSWORD environment variables are not correct. Please ensure you are using the right credentials.",
                    )
                finally:
                    test_session.close()
            else:
                # For cert, azcli, browser, just return credentials
                return credentials
        else:
            raise M365CredentialsUnavailableError(
                file=os.path.basename(__file__),
                message="No valid M365 authentication method or credentials were provided. Please check your authentication flags and environment variables."
            )

    def print_credentials(self):
        """M365 credentials information.

        This method prints the M365 Tenant Domain, M365 Tenant ID, M365 Region,
        M365 Subscriptions, M365 Identity Type, and M365 Identity ID.

        Args:
            None

        Returns:
            None
        """
        report_lines = [
            f"M365 Region: {Fore.YELLOW}{self.region_config.name}{Style.RESET_ALL}",
            f"M365 Tenant Domain: {Fore.YELLOW}{self._identity.tenant_domain}{Style.RESET_ALL} M365 Tenant ID: {Fore.YELLOW}{self._identity.tenant_id}{Style.RESET_ALL}",
            f"M365 Identity Type: {Fore.YELLOW}{self._identity.identity_type}{Style.RESET_ALL} M365 Identity ID: {Fore.YELLOW}{self._identity.identity_id}{Style.RESET_ALL}",
            f"M365 User: {Fore.YELLOW}{getattr(self.credentials, 'user', 'N/A') or 'N/A'}{Style.RESET_ALL}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the M365 credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    @staticmethod
    def setup_session(
        az_cli_auth: bool,
        sp_env_auth: bool,
        env_auth: bool,
        browser_auth: bool,
        tenant_id: str,
        m365_credentials: dict,
        region_config: M365RegionConfig,
        certificate_thumbprint: str = None,
        client_id: str = None,
        user: str = None,
    ):
        """Returns the M365 credentials object.

        Set up the M365 session with the specified authentication method.
        """
        # Certificate-based authentication (PowerShell/Graph)
        if certificate_thumbprint and client_id and tenant_id:
            # Use PowerShell-based session for cert auth (do not use DefaultAzureCredential)
            from prowler.providers.m365.models import M365Credentials
            from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
            creds = M365Credentials(
                user="",  # No user for cert auth
                passwd="",  # No password for cert auth
                client_id=client_id,
                client_secret="",  # No client secret for cert auth
                tenant_id=tenant_id,
            )
            return M365PowerShell(creds)
        if not browser_auth:
            if sp_env_auth or env_auth:
                try:
                    M365Provider.check_service_principal_creds_env_vars()
                except M365EnvironmentVariableError as environment_credentials_error:
                    logger.critical(
                        f"{environment_credentials_error.__class__.__name__}[{environment_credentials_error.__traceback__.tb_lineno}] -- {environment_credentials_error}"
                    )
                    raise environment_credentials_error
            try:
                if m365_credentials:
                    try:
                        credentials = ClientSecretCredential(
                            tenant_id=m365_credentials["tenant_id"],
                            client_id=m365_credentials["client_id"],
                            client_secret=m365_credentials["client_secret"],
                        )
                        return credentials
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365ClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except CredentialUnavailableError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365CredentialsUnavailableError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365ConfigCredentialsError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                else:
                    try:
                        credentials = DefaultAzureCredential(
                            exclude_environment_credential=not (
                                sp_env_auth or env_auth
                            ),
                            exclude_cli_credential=not az_cli_auth,
                            exclude_managed_identity_credential=True,
                            exclude_visual_studio_code_credential=True,
                            exclude_shared_token_cache_credential=True,
                            exclude_powershell_credential=True,
                            authority=region_config.authority,
                        )
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365ClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except CredentialUnavailableError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365CredentialsUnavailableError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365DefaultAzureCredentialError(
                            file=os.path.basename(__file__), original_exception=error
                        )
            except Exception as error:
                logger.critical("Failed to retrieve M365 credentials")
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise M365SetUpSessionError(
                    file=os.path.basename(__file__), original_exception=error
                )
        else:
            try:
                credentials = InteractiveBrowserCredential(tenant_id=tenant_id)
            except Exception as error:
                logger.critical(
                    "Failed to retrieve M365 credentials using browser authentication"
                )
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise M365InteractiveBrowserCredentialError(
                    file=os.path.basename(__file__), original_exception=error
                )

        return credentials

    @staticmethod
    def test_connection(
        az_cli_auth: bool = False,
        sp_env_auth: bool = False,
        env_auth: bool = False,
        browser_auth: bool = False,
        tenant_id: str = None,
        region: str = "M365Global",
        raise_on_exception=True,
        client_id=None,
        client_secret=None,
        user=None,
        encrypted_password=None,
    ) -> Connection:
        """Test connection to M365 subscription.

        Test the connection to an M365 subscription using the provided credentials.

        Args:

            az_cli_auth (bool): Flag indicating whether to use Azure CLI authentication.
            sp_env_auth (bool): Flag indicating whether to use application authentication with environment variables.
            env_auth: (bool): Flag indicating whether to use application and PowerShell authentication with environment variables.
            browser_auth (bool): Flag indicating whether to use interactive browser authentication.
            tenant_id (str): The M365 Active Directory tenant ID.
            region (str): The M365 region.
            raise_on_exception (bool): Flag indicating whether to raise an exception if the connection fails.
            client_id (str): The M365 client ID.
            client_secret (str): The M365 client secret.
            user (str): The M365 user email.
            encrypted_password (str): The M365 encrypted_password.


        Returns:
            bool: True if the connection is successful, False otherwise.

        Raises:
            Exception: If failed to test the connection to M365 subscription.
            M365ArgumentTypeValidationError: If there is an error in the argument type validation.
            M365SetUpRegionConfigError: If there is an error in setting up the region configuration.
            M365InteractiveBrowserCredentialError: If there is an error in retrieving the M365 credentials using browser authentication.
            M365HTTPResponseError: If there is an HTTP response error.
            M365ConfigCredentialsError: If there is an error in configuring the M365 credentials from a dictionary.


        Examples:
            >>> M365Provider.test_connection(az_cli_auth=True)
            True
            >>> M365Provider.test_connection(sp_env_auth=False, browser_auth=True, tenant_id=None)
            False, ArgumentTypeError: M365 Tenant ID is required only for browser authentication mode
            >>> M365Provider.test_connection(tenant_id="XXXXXXXXXX", client_id="XXXXXXXXXX", client_secret="XXXXXXXXXX")
            True
        """
        try:
            M365Provider.validate_arguments(
                az_cli_auth,
                sp_env_auth,
                env_auth,
                browser_auth,
                tenant_id,
                client_id,
                client_secret,
                user,
                encrypted_password,
            )
            region_config = M365Provider.setup_region_config(region)

            # Get the dict from the static credentials
            m365_credentials = None
            if tenant_id and client_id and client_secret:
                m365_credentials = M365Provider.validate_static_credentials(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                )

            # Set up the M365 session
            credentials = M365Provider.setup_session(
                az_cli_auth,
                sp_env_auth,
                env_auth,
                browser_auth,
                tenant_id,
                m365_credentials,
                region_config,
            )

            GraphServiceClient(credentials=credentials)

            logger.info("M365 provider: Connection to M365 successful")

            return Connection(is_connected=True)

        # Exceptions from setup_region_config
        except M365ArgumentTypeValidationError as type_validation_error:
            logger.error(
                f"{type_validation_error.__class__.__name__}[{type_validation_error.__traceback__.tb_lineno}]: {type_validation_error}"
            )
            if raise_on_exception:
                raise type_validation_error
            return Connection(error=type_validation_error)
        except M365SetUpRegionConfigError as region_config_error:
            logger.error(
                f"{region_config_error.__class__.__name__}[{region_config_error.__traceback__.tb_lineno}]: {region_config_error}"
            )
            if raise_on_exception:
                raise region_config_error
            return Connection(error=region_config_error)
        # Exceptions from setup_session
        except M365EnvironmentVariableError as environment_credentials_error:
            logger.error(
                f"{environment_credentials_error.__class__.__name__}[{environment_credentials_error.__traceback__.tb_lineno}]: {environment_credentials_error}"
            )
            if raise_on_exception:
                raise environment_credentials_error
            return Connection(error=environment_credentials_error)
        except M365ConfigCredentialsError as config_credentials_error:
            logger.error(
                f"{config_credentials_error.__class__.__name__}[{config_credentials_error.__traceback__.tb_lineno}]: {config_credentials_error}"
            )
            if raise_on_exception:
                raise config_credentials_error
            return Connection(error=config_credentials_error)
        except M365ClientAuthenticationError as client_auth_error:
            logger.error(
                f"{client_auth_error.__class__.__name__}[{client_auth_error.__traceback__.tb_lineno}]: {client_auth_error}"
            )
            if raise_on_exception:
                raise client_auth_error
            return Connection(error=client_auth_error)
        except M365CredentialsUnavailableError as credential_unavailable_error:
            logger.error(
                f"{credential_unavailable_error.__class__.__name__}[{credential_unavailable_error.__traceback__.tb_lineno}]: {credential_unavailable_error}"
            )
            if raise_on_exception:
                raise credential_unavailable_error
            return Connection(error=credential_unavailable_error)
        except (
            M365ClientIdAndClientSecretNotBelongingToTenantIdError
        ) as tenant_id_error:
            logger.error(
                f"{tenant_id_error.__class__.__name__}[{tenant_id_error.__traceback__.tb_lineno}]: {tenant_id_error}"
            )
            if raise_on_exception:
                raise tenant_id_error
            return Connection(error=tenant_id_error)
        except (
            M365TenantIdAndClientSecretNotBelongingToClientIdError
        ) as client_id_error:
            logger.error(
                f"{client_id_error.__class__.__name__}[{client_id_error.__traceback__.tb_lineno}]: {client_id_error}"
            )
            if raise_on_exception:
                raise client_id_error
            return Connection(error=client_id_error)
        except (
            M365TenantIdAndClientIdNotBelongingToClientSecretError
        ) as client_secret_error:
            logger.error(
                f"{client_secret_error.__class__.__name__}[{client_secret_error.__traceback__.tb_lineno}]: {client_secret_error}"
            )
            if raise_on_exception:
                raise client_secret_error
            return Connection(error=client_secret_error)
        # Exceptions from provider_id validation
        except M365InvalidProviderIdError as invalid_credentials_error:
            logger.error(
                f"{invalid_credentials_error.__class__.__name__}[{invalid_credentials_error.__traceback__.tb_lineno}]: {invalid_credentials_error}"
            )
            if raise_on_exception:
                raise invalid_credentials_error
            return Connection(error=invalid_credentials_error)
        # Exceptions from SubscriptionClient
        except HttpResponseError as http_response_error:
            logger.error(
                f"{http_response_error.__class__.__name__}[{http_response_error.__traceback__.tb_lineno}]: {http_response_error}"
            )
            if raise_on_exception:
                raise M365HTTPResponseError(
                    file=os.path.basename(__file__),
                    original_exception=http_response_error,
                )
            return Connection(error=http_response_error)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                # Raise directly the exception
                raise error
            return Connection(error=error)

    @staticmethod
    def check_service_principal_creds_env_vars():
        """
        Checks the presence of required environment variables for service principal authentication against Azure.

        This method checks for the presence of the following environment variables:
        - AZURE_CLIENT_ID: Azure client ID
        - AZURE_TENANT_ID: Azure tenant ID
        - AZURE_CLIENT_SECRET: Azure client secret

        If any of the environment variables is missing, it logs a critical error and exits the program.
        """
        logger.info(
            "M365 provider: checking service principal environment variables  ..."
        )
        for env_var in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"]:
            if not getenv(env_var):
                logger.critical(
                    f"M365 provider: Missing environment variable {env_var} needed to authenticate against M365."
                )
                raise M365EnvironmentVariableError(
                    file=os.path.basename(__file__),
                    message=f"Missing environment variable {env_var} required to authenticate.",
                )

    def setup_identity(
        self,
        az_cli_auth,
        sp_env_auth,
        env_auth,
        browser_auth,
        client_id,
    ):
        """
        Sets up the identity for the M365 provider.
        """
        from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
        import subprocess
        import json
        identity = M365IdentityInfo()
        # If using PowerShell-based session (certificate auth), skip Graph API
        if isinstance(self.session, M365PowerShell):
            identity.tenant_id = self.tenant_id if self.tenant_id else "N/A"
            identity.identity_id = self.client_id if self.client_id else "N/A"
            identity.identity_type = "Service Principal"
            # Retrieve tenant domain from Get-MgOrganization with authentication
            try:
                ps_script = f'''
                Connect-MgGraph -CertificateThumbprint "{self.certificate_thumbprint}" -ClientId "{self.client_id}" -TenantId "{self.tenant_id}" -NoWelcome
                $org = Get-MgOrganization
                $primaryDomain = $org.VerifiedDomains | Where-Object {{ $_.IsDefault -eq $true }} | Select-Object -First 1 -ExpandProperty Name
                if (-not $primaryDomain) {{
                    $primaryDomain = $org.VerifiedDomains | Select-Object -First 1 -ExpandProperty Name
                }}
                $primaryDomain | ConvertTo-Json
                '''
                result = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True)
                if result.returncode == 0 and result.stdout:
                    domain = json.loads(result.stdout)
                    identity.tenant_domain = domain if domain else (self.organization if self.organization else "N/A")
                else:
                    identity.tenant_domain = self.organization if self.organization else "N/A"
            except Exception as e:
                identity.tenant_domain = self.organization if self.organization else "N/A"
            return identity
        # If credentials comes from service principal or browser, if the required permissions are assigned
        # the identity can access AAD and retrieve the tenant domain name.
        # With cli also should be possible but right now it does not work, m365 python package issue is coming
        # At the time of writting this with az cli creds is not working, despite that is included
        if env_auth or az_cli_auth or sp_env_auth or browser_auth or client_id:

            async def get_m365_identity():
                # Trying to recover tenant domain info
                try:
                    logger.info(
                        "Trying to retrieve tenant domain from AAD to populate identity structure ..."
                    )
                    client = GraphServiceClient(credentials=self.session)

                    domain_result = await client.domains.get()
                    if getattr(domain_result, "value"):
                        if getattr(domain_result.value[0], "id"):
                            identity.tenant_domain = domain_result.value[0].id

                except HttpResponseError as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    raise M365HTTPResponseError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                    )
                except ClientAuthenticationError as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    raise M365GetTokenIdentityError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                # since that exception is not considered as critical, we keep filling another identity fields
                if sp_env_auth or env_auth or client_id:
                    # The id of the sp can be retrieved from environment variables
                    identity.identity_id = getenv("AZURE_CLIENT_ID")
                    identity.identity_type = "Service Principal"
                # Same here, if user can access AAD, some fields are retrieved if not, default value, for az cli
                # should work but it doesn't, pending issue
                else:
                    identity.identity_id = "Unknown user id (Missing AAD permissions)"
                    identity.identity_type = "User"
                    try:
                        logger.info(
                            "Trying to retrieve user information from AAD to populate identity structure ..."
                        )
                        client = GraphServiceClient(credentials=self.session)

                        me = await client.me.get()
                        if me:
                            if getattr(me, "user_principal_name"):
                                identity.identity_id = me.user_principal_name

                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )

                # Retrieve tenant id from the client
                client = GraphServiceClient(credentials=self.session)
                organization_info = await client.organization.get()
                identity.tenant_id = organization_info.value[0].id

            asyncio.get_event_loop().run_until_complete(get_m365_identity())
            return identity

    @staticmethod
    def validate_static_credentials(
        tenant_id: str = None, client_id: str = None, client_secret: str = None
    ) -> dict:
        """
        Validates the static credentials for the M365 provider.

        Args:
            tenant_id (str): The M365 Active Directory tenant ID.
            client_id (str): The M365 client ID.
            client_secret (str): The M365 client secret.

        Raises:
            M365NotValidTenantIdError: If the provided M365 Tenant ID is not valid.
            M365NotValidClientIdError: If the provided M365 Client ID is not valid.
            M365NotValidClientSecretError: If the provided M365 Client Secret is not valid.
            M365ClientIdAndClientSecretNotBelongingToTenantIdError: If the provided M365 Client ID and Client Secret do not belong to the specified Tenant ID.
            M365TenantIdAndClientSecretNotBelongingToClientIdError: If the provided M365 Tenant ID and Client Secret do not belong to the specified Client ID.
            M365TenantIdAndClientIdNotBelongingToClientSecretError: If the provided M365 Tenant ID and Client ID do not belong to the specified Client Secret.

        Returns:
            dict: A dictionary containing the validated static credentials.
        """
        # Validate the Tenant ID
        try:
            UUID(tenant_id)
        except ValueError:
            raise M365NotValidTenantIdError(
                file=os.path.basename(__file__),
                message="The provided M365 Tenant ID is not valid.",
            )

        # Validate the Client ID
        try:
            UUID(client_id)
        except ValueError:
            raise M365NotValidClientIdError(
                file=os.path.basename(__file__),
                message="The provided M365 Client ID is not valid.",
            )
        # Validate the Client Secret
        if not re.match("^[a-zA-Z0-9._~-]+$", client_secret):
            raise M365NotValidClientSecretError(
                file=os.path.basename(__file__),
                message="The provided M365 Client Secret is not valid.",
            )

        try:
            M365Provider.verify_client(tenant_id, client_id, client_secret)
            return {
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret,
            }
        except M365NotValidTenantIdError as tenant_id_error:
            logger.error(
                f"{tenant_id_error.__class__.__name__}[{tenant_id_error.__traceback__.tb_lineno}]: {tenant_id_error}"
            )
            raise M365ClientIdAndClientSecretNotBelongingToTenantIdError(
                file=os.path.basename(__file__),
                message="The provided M365 Client ID and Client Secret do not belong to the specified Tenant ID.",
            )
        except M365NotValidClientIdError as client_id_error:
            logger.error(
                f"{client_id_error.__class__.__name__}[{client_id_error.__traceback__.tb_lineno}]: {client_id_error}"
            )
            raise M365TenantIdAndClientSecretNotBelongingToClientIdError(
                file=os.path.basename(__file__),
                message="The provided M365 Tenant ID and Client Secret do not belong to the specified Client ID.",
            )
        except M365NotValidClientSecretError as client_secret_error:
            logger.error(
                f"{client_secret_error.__class__.__name__}[{client_secret_error.__traceback__.tb_lineno}]: {client_secret_error}"
            )
            raise M365TenantIdAndClientIdNotBelongingToClientSecretError(
                file=os.path.basename(__file__),
                message="The provided M365 Tenant ID and Client ID do not belong to the specified Client Secret.",
            )

    @staticmethod
    def verify_client(tenant_id, client_id, client_secret) -> None:
        """
        Verifies the M365 client credentials using the specified tenant ID, client ID, and client secret.

        Args:
            tenant_id (str): The M365 Active Directory tenant ID.
            client_id (str): The M365 client ID.
            client_secret (str): The M365 client secret.

        Raises:
            M365NotValidTenantIdError: If the provided M365 Tenant ID is not valid.
            M365NotValidClientIdError: If the provided M365 Client ID is not valid.
            M365NotValidClientSecretError: If the provided M365 Client Secret is not valid.

        Returns:
            None
        """
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        try:
            # Create a ConfidentialClientApplication instance
            app = ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=authority,
            )

            # Attempt to acquire a token
            result = app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )

            # Check if token acquisition was successful
            if "access_token" not in result:
                # Handle specific errors based on the MSAL response
                error_description = result.get("error_description", "")
                if f"Tenant '{tenant_id}'" in error_description:
                    raise M365NotValidTenantIdError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Tenant ID is not valid for the specified Client ID and Client Secret.",
                    )
                if f"Application with identifier '{client_id}'" in error_description:
                    raise M365NotValidClientIdError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Client ID is not valid for the specified Tenant ID and Client Secret.",
                    )
                if "Invalid client secret provided" in error_description:
                    raise M365NotValidClientSecretError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Client Secret is not valid for the specified Tenant ID and Client ID.",
                    )

        except Exception as e:
            # Generic exception handling (if needed)
            raise RuntimeError(f"An unexpected error occurred: {str(e)}")

    def get_checks_to_execute_by_audit_resources(self):
        """
        Stub for get_checks_to_execute_by_audit_resources to avoid AttributeError.
        Returns an empty set for now.
        """
        return set()
