# M365 Certificate Authentication Setup

## Prerequisites

1. PowerShell Modules:
   ```powershell
   Install-Module -Name Microsoft.Graph.Authentication
   Install-Module -Name MicrosoftTeams
   Install-Module -Name ExchangeOnlineManagement
   Install-Module -Name Microsoft.PowerShell.SecretManagement
   ```

2. Certificate Requirements:
   - A valid certificate with private key
   - Certificate must be installed in the Windows Certificate Store
   - Certificate must have the following properties:
     - Key Usage: Digital Signature
     - Enhanced Key Usage: Client Authentication
     - Subject Alternative Name: Must include the application ID (client ID)

## Certificate Setup Process

1. Create a self-signed certificate (if needed):
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=ProwlerM365" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
   ```

2. Export the certificate (if needed):
   ```powershell
   $cert | Export-Certificate -FilePath "C:\path\to\cert.cer"
   ```

3. Note the certificate thumbprint:
   ```powershell
   $cert.Thumbprint
   ```

4. Register the application in Azure AD:
   - Go to Azure Portal > Azure Active Directory > App registrations
   - Create a new registration
   - Note the Application (client) ID
   - Upload the certificate in the "Certificates & secrets" section

5. Grant necessary API permissions:
   - Microsoft Graph: Required permissions for the services you'll access
   - Exchange Online: Exchange.ManageAsApp
   - Microsoft Teams: Teams.Read.All
   - IPPS: Compliance.Read.All

## Using Certificate Authentication

Run Prowler with the certificate authentication parameters:

```powershell
python prowler-cli.py m365 \
    --cert-auth \
    --cert-thumbprint "YOUR_CERT_THUMBPRINT" \
    --app-id "YOUR_APP_ID" \
    --tenant-id "YOUR_TENANT_ID" \
    --organization "yourdomain.com"
```

Alternative argument names:
- `--certificate-thumbprint` can be used instead of `--cert-thumbprint`
- `--application-id` can be used instead of `--app-id`

## Troubleshooting

1. Certificate not found:
   - Verify the certificate is installed in the correct store
   - Check the thumbprint matches exactly
   - Ensure the certificate has a private key

2. Authentication failures:
   - Verify the application has the correct permissions
   - Check the certificate's validity period
   - Ensure the certificate's subject alternative name includes the application ID

3. Service connection issues:
   - Verify the required PowerShell modules are installed
   - Check network connectivity to M365 services
   - Ensure the organization domain is correct for Exchange Online and IPPS 