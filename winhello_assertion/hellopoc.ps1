
# Get Hello cert
$certs = get-childitem Cert:\CurrentUser\My\ | where { $_.subject -like "*login.windows.net*" }
$cert = $certs[0];
$targetuser = $cert.Subject.Split('/')[-1]
Write-Host Found cert with $cert.Subject
$signature = @"
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
public struct BCRYPT_PKCS1_PADDING_INFO {
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pszAlgId;
}
[DllImport("ncrypt.dll", SetLastError = true)]
public static extern int NCryptOpenStorageProvider(
    ref IntPtr phProvider,
    [MarshalAs(UnmanagedType.LPWStr)]
    string pszProviderName,
    uint dwFlags
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
public static extern int NCryptGetProperty(
    IntPtr hObject,
    [MarshalAs(UnmanagedType.LPWStr)]
    string pszProperty,
    byte[] pbOutput,
    int cbOutput,
    ref int pcbResult,
    int dwFlags
);
[DllImport("ncrypt.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int NCryptFreeObject(
    IntPtr hObject
);
[DllImport("crypt32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptAcquireCertificatePrivateKey(
    IntPtr pCert,
    int dwFlags,
    IntPtr pvReserved,
    ref IntPtr phCryptProv,
    ref uint pdwKeySpec,
    ref bool pfCallerFreeProv
);
[DllImport("ncrypt.dll", SetLastError=false)]
public static extern int NCryptSignHash(
    IntPtr hKey,
    IntPtr pPaddingInfo,
    [MarshalAs(UnmanagedType.LPArray)]
    byte[] pbHashValue,
    int cbHashValue,
    [MarshalAs(UnmanagedType.LPArray)]
    byte[] pbSignature,
    int cbSignature,
    ref int pcbResult,
    int dwFlags
);
[DllImport("ncrypt.dll", SetLastError=false)]
public static extern int NCryptVerifySignature(
    IntPtr hKey,
    IntPtr pPaddingInfo,
    [MarshalAs(UnmanagedType.LPArray)]
    byte[] pbHashValue,
    int cbHashValue,
    [MarshalAs(UnmanagedType.LPArray)]
    byte[] pbSignature,
    int cbSignature,
    int dwFlags
);
"@
Add-Type -MemberDefinition $signature -Namespace NCrypt -Name Native
$CERT_KEY_PROV_INFO_PROP_ID = 0x2 # from Wincrypt.h header file
$pcbData = 0
[void][NCrypt.Native]::CertGetCertificateContextProperty($cert.Handle,$CERT_KEY_PROV_INFO_PROP_ID,[IntPtr]::Zero,[ref]$pcbData)
$pvData = [Runtime.InteropServices.Marshal]::AllocHGlobal($pcbData)
[NCrypt.Native]::CertGetCertificateContextProperty($cert.Handle,$CERT_KEY_PROV_INFO_PROP_ID,$pvData,[ref]$pcbData)
$keyProv = [Runtime.InteropServices.Marshal]::PtrToStructure($pvData,[type][NCrypt.Native+CRYPT_KEY_PROV_INFO])
[Runtime.InteropServices.Marshal]::FreeHGlobal($pvData)
$phProvider = [IntPtr]::Zero
[void][NCrypt.Native]::NCryptOpenStorageProvider([ref]$phProvider,$keyProv.pwszProvName,0)
$phKey = [IntPtr]::Zero
[void][NCrypt.Native]::NCryptOpenKey($phProvider,[ref]$phKey,$keyProv.pwszContainerName,0,0)


$pcbResult = 0
# call NCryptSignHash function by passing private key handle and hash data
$thing = [IntPtr]::Zero
$thing2 = [IntPtr]::Zero
[NCrypt.Native]::NCryptExportKey($phKey,$thing,"RSAPUBLICBLOB",$thing2,$null,$pcbResult,[ref]$pcbResult,0)
$thing = [IntPtr]::Zero
$thing2 = [IntPtr]::Zero
$pubkey = New-Object byte[] -ArgumentList $pcbResult
[NCrypt.Native]::NCryptExportKey($phKey,$thing,"RSAPUBLICBLOB",$thing2,$pubkey,$pubkey.length,[ref]$pcbResult,0)

# Write-Host pcbResult: $pcbResult


$hasher = [Security.Cryptography.SHA256]::Create()
[Byte[]]$hash = $hasher.ComputeHash($pubkey)
$hasher.Dispose()
$kid =  [Convert]::ToBase64String($hash)
write-host KeyId: $kid

$nonce = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body "grant_type=srv_challenge").Nonce

$header = [Ordered]@{
    typ = "JWT"
    alg = "RS256"
    kid = $kid
    use = "ngc"
} | ConvertTo-Json
$encheader = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)) -replace '\+','-' -replace '/','_' -replace '='

$now = (Get-Date).ToUniversalTime()
$createDate = [Math]::Floor([decimal](Get-Date($now) -UFormat "%s"))
$expiryDate = [Math]::Floor([decimal](Get-Date($now.AddHours(2)) -UFormat "%s"))
$rawclaims = [Ordered]@{
    iss = $targetuser
    aud = "common"
    iat = $createDate
    exp = $expiryDate
    scope = "openid aza ugs"
    request_nonce = $nonce
} | ConvertTo-Json
$encbody = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rawclaims)) -replace '\+','-' -replace '/','_' -replace '='
$jwt = $encheader + '.' + $encbody # The first part of the JWT

$toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)
$hasher = [Security.Cryptography.SHA256]::Create()
[Byte[]]$hash = $hasher.ComputeHash($toSign)
$hasher.Dispose()

$st = New-Object -TypeName 'NCrypt.Native+BCRYPT_PKCS1_PADDING_INFO'
$st.pszAlgId = "SHA256"
$pPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($st));
[Runtime.InteropServices.Marshal]::StructureToPtr($st, $pPtr, $false);
$pcbResult = 0
# call NCryptSignHash function by passing private key handle and hash data
[NCrypt.Native]::NCryptSignHash($phKey,$pPtr,$hash,$hash.length,$null,$pcbResult,[ref]$pcbResult,2)
# Write-Host pcbResult: $pcbResult
$pbSignature = New-Object byte[] -ArgumentList $pcbResult
[NCrypt.Native]::NCryptSignHash($phKey,$pPtr,$hash,$hash.length,$pbSignature,$pbSignature.length,[ref]$pcbResult,2)

$sig = [Convert]::ToBase64String($pbSignature) -replace '\+','-' -replace '/','_' -replace '='
$assertion = $jwt + '.' + $sig
write-host Assertion: $assertion
