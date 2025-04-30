"""Common arguments for all providers."""
from argparse import ArgumentParser, Namespace


def init_providers_parser(parser_instance: ArgumentParser) -> None:
    """Initialize provider-specific argument parsers."""
    # AWS Provider
    aws_parser = parser_instance.subparsers.add_parser(
        "aws",
        parents=[parser_instance.common_providers_parser],
        help="AWS Provider",
    )
    # Add AWS-specific arguments here...

    # M365 Provider
    m365_parser = parser_instance.subparsers.add_parser(
        "m365",
        parents=[parser_instance.common_providers_parser],
        help="Microsoft 365 Provider",
    )
    m365_auth = m365_parser.add_argument_group("Authentication Methods")
    m365_auth.add_argument(
        "--cert-auth",
        action="store_true",
        help="Use certificate authentication for M365",
    )
    m365_auth.add_argument(
        "--app-id",
        "--application-id",
        help="Application ID (client ID) for M365 authentication",
    )
    m365_auth.add_argument(
        "--tenant-id",
        help="Tenant ID for M365 authentication",
    )
    m365_auth.add_argument(
        "--cert-thumbprint",
        "--certificate-thumbprint",
        help="Certificate thumbprint for M365 authentication",
    )
    m365_auth.add_argument(
        "--organization",
        help="Organization domain for Exchange Online and IPPS authentication",
    )


def validate_provider_arguments(args: Namespace) -> tuple[bool, str]:
    """
    Validate provider-specific arguments.

    Args:
        args: The parsed command line arguments

    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    if args.provider == "m365":
        # Check if certificate authentication parameters are provided
        if args.cert_auth:
            # All certificate auth parameters must be provided together
            if not all([args.cert_thumbprint, args.app_id, args.tenant_id]):
                return (
                    False,
                    "When using certificate authentication (--cert-auth), all of --cert-thumbprint, --app-id, and --tenant-id must be provided",
                )
            # Organization is required for Exchange Online and IPPS
            if args.service and any(s in ["exchange", "ipps"] for s in args.service) and not args.organization:
                return (
                    False,
                    "Organization domain (--organization) is required for Exchange Online and IPPS services",
                )

    return True, "" 