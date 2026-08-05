# WebAuthn Assertion Generator using Windows Hello Keys
# Compatible with ROADtools WebAuthn implementation

param(
    [Parameter(Mandatory=$true)]
    [string]$Challenge,

    [Parameter(Mandatory=$true)]
    [string]$UserId,
    
    [Parameter(Mandatory=$false)]
    [string]$RpId = "login.microsoft.com",
    
    [Parameter(Mandatory=$false)]
    [string]$Origin = "https://login.microsoft.com",
    
    [Parameter(Mandatory=$false)]
    [int]$SignCount = 0
)

# NCrypt Native API definitions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NCrypt {
    [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CertGetCertificateContextProperty(
        IntPtr pCertContext,
        uint dwPropId,
        IntPtr pvData,
        ref uint pcbData
    );

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CRYPT_KEY_PROV_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszContainerName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [DllImport("ncrypt.dll", SetLastError = true)]
    public static extern int NCryptOpenStorageProvider(
        ref IntPtr phProvider,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pszProviderName,
        uint dwFlags
    );

    [DllImport("ncrypt.dll", SetLastError = true)]
    public static extern int NCryptOpenKey(
        IntPtr hProvider,
        ref IntPtr phKey,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pszKeyName,
        uint dwLegacyKeySpec,
        uint dwFlags
    );

    [DllImport("ncrypt.dll", SetLastError = true)]
    public static extern int NCryptSignHash(
        IntPtr hKey,
        IntPtr pPaddingInfo,
        byte[] pbHashValue,
        int cbHashValue,
        byte[] pbSignature,
        int cbSignature,
        ref int pcbResult,
        int dwFlags
    );

    [DllImport("ncrypt.dll", SetLastError = true)]
    public static extern int NCryptExportKey(
        IntPtr hKey,
        IntPtr hExportKey,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pszBlobType,
        IntPtr pParameterList,
        [MarshalAs(UnmanagedType.LPArray)]
        byte[] pbOutput,
        int cbOutput,
        ref int pcbResult,
        int dwFlags
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_PKCS1_PADDING_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pszAlgId;
    }
}
"@

function Get-Base64UrlEncode {
    param([byte[]]$Bytes)
    $base64 = [Convert]::ToBase64String($Bytes)
    return $base64.Replace('+', '-').Replace('/', '_').Replace('=', '')
}

function Get-Base64UrlDecode {
    param([string]$Base64Url)
    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    # Add padding
    while ($base64.Length % 4 -ne 0) {
        $base64 += '='
    }
    return [Convert]::FromBase64String($base64)
}

function Convert-GuidToLittleEndian {
    param([Guid]$Guid)
    $bytes = $Guid.ToByteArray()
    return $bytes
}

function Get-UserHandleFromCert {
    param($Certificate, $userId)
    
    # Parse certificate subject: CN=upn/tenantId/userId
    $subject = $Certificate.Subject
    Write-Host "Certificate Subject: $subject"
    
    # Extract tenant and user IDs from subject
    # Format is typically: CN={sid}/{unknown}/login.windows.net/{tenantId}/{upn}
    $parts = $subject -split '/'
    
    if ($parts.Length -lt 3) {
        Write-Error "Cannot parse certificate subject. Expected format: CN=../tenantId/userId"
        return $null
    }
    
    # Get the tenant ID
    $tenantId = $parts[-2]
    
    Write-Host "Tenant ID: $tenantId"
    Write-Host "User ID: $userId"
    
    # Convert GUIDs to Little-Endian bytes
    try {
        $tenantGuid = [Guid]$tenantId
        $userGuid = [Guid]$userId
    } catch {
        Write-Error "Failed to parse GUIDs from certificate subject"
        return $null
    }
    
    $tenantBytes = Convert-GuidToLittleEndian -Guid $tenantGuid
    $userBytes = Convert-GuidToLittleEndian -Guid $userGuid
    
    # Calculate userHandle: "ON:" + tenantId (LE) + SHA256(userId LE)
    $userHandleBytes = [System.Collections.ArrayList]::new()
    [void]$userHandleBytes.AddRange([byte[]][char[]]"ON:")
    [void]$userHandleBytes.AddRange($tenantBytes)
    
    # Calculate SHA256 of user ID bytes
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $userHash = $sha256.ComputeHash($userBytes)
    [void]$userHandleBytes.AddRange($userHash)
    $sha256.Dispose()
    
    $userHandle = Get-Base64UrlEncode -Bytes $userHandleBytes.ToArray()
    
    Write-Host "User Handle: $userHandle"
    
    return @{
        TenantId = $tenantId
        UserId = $userId
        UserHandle = $userHandle
    }
}

# Main execution
Write-Host "=== WebAuthn Assertion Generator using Windows Hello ===" -ForegroundColor Cyan
Write-Host ""

# Find Windows Hello certificate
Write-Host "Looking for Windows Hello certificate..."
$certs = Get-ChildItem Cert:\CurrentUser\My\ | Where-Object { $_.Subject -like "*login.windows.net*" }

if ($certs.Count -eq 0) {
    Write-Error "No Windows Hello certificate found"
    exit 1
}

$cert = $certs[0]
Write-Host "Found certificate: $($cert.Subject)" -ForegroundColor Green

# Extract user info from certificate
$userInfo = Get-UserHandleFromCert -Certificate $cert -userId $UserId
if (-not $userInfo) {
    exit 1
}

# Get key provider info
$certHandle = $cert.Handle
$propSize = 0
$propId = 2  # CERT_KEY_PROV_INFO_PROP_ID

[void][NCrypt]::CertGetCertificateContextProperty($certHandle, $propId, [IntPtr]::Zero, [ref]$propSize)
$propBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($propSize)
[void][NCrypt]::CertGetCertificateContextProperty($certHandle, $propId, $propBuffer, [ref]$propSize)

$keyProv = [Runtime.InteropServices.Marshal]::PtrToStructure($propBuffer, [Type][NCrypt+CRYPT_KEY_PROV_INFO])
[Runtime.InteropServices.Marshal]::FreeHGlobal($propBuffer)

Write-Host "Key Container: $($keyProv.pwszContainerName)"
Write-Host "Key Provider: $($keyProv.pwszProvName)"

# Open NCrypt storage provider and key
$phProvider = [IntPtr]::Zero
[void][NCrypt]::NCryptOpenStorageProvider([ref]$phProvider, $keyProv.pwszProvName, 0)

$phKey = [IntPtr]::Zero
[void][NCrypt]::NCryptOpenKey($phProvider, [ref]$phKey, $keyProv.pwszContainerName, 0, 0)

# Export public key for credential ID calculation
$pcbResult = 0
[NCrypt]::NCryptExportKey($phKey, [IntPtr]::Zero, "RSAPUBLICBLOB", [IntPtr]::Zero, $null, 0, [ref]$pcbResult, 0)
$pubkey = New-Object byte[] -ArgumentList $pcbResult
[NCrypt]::NCryptExportKey($phKey, [IntPtr]::Zero, "RSAPUBLICBLOB", [IntPtr]::Zero, $pubkey, $pubkey.Length, [ref]$pcbResult, 0)

# Calculate credential ID (SHA256 of public key)
$sha256 = [Security.Cryptography.SHA256]::Create()
$credIdHash = $sha256.ComputeHash($pubkey)
$sha256.Dispose()
$credentialId = Get-Base64UrlEncode -Bytes $credIdHash

Write-Host "Credential ID: $credentialId" -ForegroundColor Green

# Base64 encode challenge
$challengebytes =  [System.Text.Encoding]::UTF8.GetBytes($Challenge)
$challengeb64 = Get-Base64UrlEncode -Bytes $challengebytes


# Create clientDataJSON
$clientData = @{
    type = "webauthn.get"
    challenge = $challengeb64
    origin = $Origin
    crossOrigin = $false
} | ConvertTo-Json -Compress

$clientDataBytes = [System.Text.Encoding]::UTF8.GetBytes($clientData)
$clientDataB64 = Get-Base64UrlEncode -Bytes $clientDataBytes

Write-Host "Client Data JSON created"

# Hash clientDataJSON
$sha256 = [Security.Cryptography.SHA256]::Create()
$clientDataHash = $sha256.ComputeHash($clientDataBytes)
$sha256.Dispose()

# Create authenticatorData
# RP ID hash (32 bytes) + flags (1 byte) + sign count (4 bytes) = 37 bytes
$rpIdBytes = [System.Text.Encoding]::UTF8.GetBytes($RpId)
$sha256 = [Security.Cryptography.SHA256]::Create()
$rpIdHash = $sha256.ComputeHash($rpIdBytes)
$sha256.Dispose()

$flags = 0x05  # UP (0x01) + UV (0x04)
$signCountBytes = [BitConverter]::GetBytes([int]$SignCount)
[Array]::Reverse($signCountBytes)  # Big-endian

$authenticatorData = [byte[]]::new(37)
[Array]::Copy($rpIdHash, 0, $authenticatorData, 0, 32)
$authenticatorData[32] = $flags
[Array]::Copy($signCountBytes, 0, $authenticatorData, 33, 4)

$authenticatorDataB64 = Get-Base64UrlEncode -Bytes $authenticatorData

Write-Host "Authenticator Data created"

# Create data to sign: authenticatorData || hash(clientDataJSON)
$toSign = [byte[]]::new($authenticatorData.Length + $clientDataHash.Length)
[Array]::Copy($authenticatorData, 0, $toSign, 0, $authenticatorData.Length)
[Array]::Copy($clientDataHash, 0, $toSign, $authenticatorData.Length, $clientDataHash.Length)

# Hash the data to sign
$sha256 = [Security.Cryptography.SHA256]::Create()
$hashToSign = $sha256.ComputeHash($toSign)
$sha256.Dispose()

Write-Host "Signing assertion with Windows Hello key..."

# Sign with NCrypt
$paddingInfo = New-Object -TypeName 'NCrypt+BCRYPT_PKCS1_PADDING_INFO'
$paddingInfo.pszAlgId = "SHA256"
$pPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($paddingInfo))
[Runtime.InteropServices.Marshal]::StructureToPtr($paddingInfo, $pPtr, $false)

$sigSize = 0
[NCrypt]::NCryptSignHash($phKey, $pPtr, $hashToSign, $hashToSign.Length, $null, 0, [ref]$sigSize, 2)

$signature = New-Object byte[] -ArgumentList $sigSize
[NCrypt]::NCryptSignHash($phKey, $pPtr, $hashToSign, $hashToSign.Length, $signature, $signature.Length, [ref]$sigSize, 2)

[Runtime.InteropServices.Marshal]::FreeHGlobal($pPtr)

$signatureB64 = Get-Base64UrlEncode -Bytes $signature

Write-Host "Signature created" -ForegroundColor Green

# Construct WebAuthn assertion response
$assertion = @{
    id = $credentialId
    clientDataJSON = $clientDataB64
    authenticatorData = $authenticatorDataB64
    signature = $signatureB64
    userHandle = $userInfo.UserHandle
}

Write-Host ""
Write-Host "=== WebAuthn Assertion ===" -ForegroundColor Cyan
Write-Host ""
Write-Host ($assertion | ConvertTo-Json -Depth 10)
Write-Host ""

# Also output as a single line JSON for easy copy-paste
Write-Host "=== Single Line JSON ===" -ForegroundColor Cyan
Write-Host ($assertion | ConvertTo-Json -Compress)

# Return the assertion object
return $assertion