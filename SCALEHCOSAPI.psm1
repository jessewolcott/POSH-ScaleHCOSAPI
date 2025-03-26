# ScaleHCOSAPI.psm1
<#
.SYNOPSIS
    PowerShell module for securely interacting with Scale Computing's HCOS REST API.
#>

#script:HCOSGA = '9.4.27.217089'
#$script:ApiEndpoint = 'https://api.scalecomputing.com/api/v2'
$script:EnableLogging = $true
$script:Credentials = @{}

function Get-ScaleHCOSModuleRoot {
    [CmdletBinding()]
    param()
    
    # First try using $PSScriptRoot which exists in PS 3.0+
    if ($PSScriptRoot) {
        return $PSScriptRoot
    }
    
    # For modules, try using the module path
    if ($ExecutionContext.SessionState.Module.Path) {
        return Split-Path -Parent -Path $ExecutionContext.SessionState.Module.Path
    }
    
    # Try using $MyInvocation which might work in some contexts
    if ($MyInvocation.MyCommand.Path) {
        return Split-Path -Parent -Path $MyInvocation.MyCommand.Path
    }
    
    # As a last resort when code is run interactively (like in VSCode snippets)
    if (Test-Path -Path $MyInvocation.PSScriptRoot) {
        return $MyInvocation.PSScriptRoot
    }
    
    # Absolute fallback - use current location (less reliable but better than nothing)
    Write-Warning "Unable to determine module path accurately, using current location"
    return $PWD.Path
}

# Initialize paths using our safe directory detection function
$script:ModuleRoot = Get-ScaleHCOSModuleRoot
$script:CredentialFolder = Join-Path -Path $script:ModuleRoot -ChildPath "Credentials"

function Write-ScaleHCOSLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    if (-not $script:EnableLogging) {
        return
    }
    
    $logDirectory = Join-Path -Path $script:ModuleRoot -ChildPath "Logs"
    
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory | Out-Null
    }
    
    $logFile = Join-Path -Path $logDirectory -ChildPath "ScaleComputing_$(Get-Date -Format 'yyyy-MM-dd').log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
}

function Initialize-ScaleHCOSEnvironment {
    [CmdletBinding()]
    param()
    
    # Ensure module root is set
    if (-not $script:ModuleRoot) {
        $script:ModuleRoot = Get-ScaleHCOSModuleRoot
    }
    
    # Create credentials folder if it doesn't exist
    try {
        if (-not (Test-Path -Path $script:CredentialFolder)) {
            New-Item -Path $script:CredentialFolder -ItemType Directory -Force | Out-Null
            Write-ScaleHCOSLog -Message "Created credentials directory: $($script:CredentialFolder)" -Level 'Info'
        }
    } catch {
        Write-ScaleHCOSLog -Message "Failed to create credentials directory: $_" -Level 'Error'
        # Create in home directory as fallback
        $script:CredentialFolder = Join-Path -Path (Get-Item ~).FullName -ChildPath ".ScaleFM"
        if (-not (Test-Path -Path $script:CredentialFolder)) {
            New-Item -Path $script:CredentialFolder -ItemType Directory -Force | Out-Null
        }
    }
    # Create logs folder if it doesn't exist
    $logDirectory = Join-Path -Path $script:ModuleRoot -ChildPath "Logs"
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory | Out-Null
    }
    
    # Ensure ApiKeys dictionary is initialized
    if ($null -eq $script:ApiKeys) {
        $script:ApiKeys = @{}
    }
    
    # Load any existing credential files into memory
    $credFiles = Get-ChildItem -Path $script:CredentialFolder -Filter "*.cred" -ErrorAction SilentlyContinue
    foreach ($file in $credFiles) {
        $roleName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $script:ApiKeys[$roleName] = $file.FullName
    }
}

# Register username and password credentials
function Register-ScaleHCOSCredentials {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [string]$Password,
        
        [Parameter(Mandatory = $false)]
        [string]$FriendlyName,

        [Parameter(Mandatory = $false)]
        [string]$EncryptionKeyFile,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    # Set logging state
    $script:EnableLogging = $EnableLogging
    
    # Initialize environment
    Initialize-ScaleHCOSEnvironment
    
    # Either use provided FriendlyName or prompt for it
    if ([string]::IsNullOrWhiteSpace($FriendlyName)) {
        $credentialName = Read-Host -Prompt "Enter a friendly name for this credential (e.g., OrgAdmin, ReadOnly)"
    } else {
        $credentialName = $FriendlyName
        Write-ScaleHCOSLog -Message "Using provided friendly name: $credentialName" -Level 'Info'
    }
    
    # Either use provided credentials or prompt for them
    if ([string]::IsNullOrWhiteSpace($Username)) {
        $Username = Read-Host -Prompt "Enter username"
    } else {
        Write-ScaleHCOSLog -Message "Using provided username" -Level 'Info'
    }
    
    if ([string]::IsNullOrWhiteSpace($Password)) {
        $passwordSecure = Read-Host -Prompt "Enter password" -AsSecureString
    } else {
        # Convert plain text password to SecureString
        $passwordSecure = ConvertTo-SecureString -String $Password -AsPlainText -Force
        Write-ScaleHCOSLog -Message "Using provided password" -Level 'Info'
    }
    
    try {
        # Create a PSCredential object with username and password
        $credential = New-Object System.Management.Automation.PSCredential ($Username, $passwordSecure)
        
        # Convert credential to encrypted standard string
        if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
            # For non-Windows PS Core, we need a key file
            if (-not $EncryptionKeyFile) {
                $keyFilePath = Join-Path -Path $script:CredentialFolder -ChildPath "encryption.key"
                if (-not (Test-Path -Path $keyFilePath)) {
                    $keyBytes = New-Object byte[] 32
                    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                    $rng.GetBytes($keyBytes)
                    $keyBytes | Set-Content -Path $keyFilePath -Encoding Byte
                }
                $EncryptionKeyFile = $keyFilePath
            }
            
            $keyBytes = Get-Content -Path $EncryptionKeyFile -Encoding Byte -Raw
            
            # Export credential as XML and encrypt it
            $credentialXml = [System.Management.Automation.PSSerializer]::Serialize($credential)
            $encryptedCredential = Protect-Data -Data $credentialXml -Key $keyBytes
        } else {
            # Windows can use DPAPI
            $credentialXml = [System.Management.Automation.PSSerializer]::Serialize($credential)
            $encryptedCredential = Protect-Data -Data $credentialXml
        }
        
        # Create credentials folder if it doesn't exist
        if (-not (Test-Path -Path $script:CredentialFolder)) {
            New-Item -Path $script:CredentialFolder -ItemType Directory -Force | Out-Null
            Write-ScaleHCOSLog -Message "Created credentials directory: $($script:CredentialFolder)" -Level 'Info'
        }
        
        # Save encrypted credential to file
        $credentialFile = Join-Path -Path $script:CredentialFolder -ChildPath "$credentialName.cred"
        $encryptedCredential | Set-Content -Path $credentialFile -Force
        
        Write-ScaleHCOSLog -Message "Credentials stored successfully with friendly name: $credentialName" -Level 'Info'
        Write-Host "Credentials stored successfully with friendly name: $credentialName" -ForegroundColor Green
        
        # Add to the in-memory credentials dictionary
        $script:Credentials[$credentialName] = $credentialFile
        
        # Return success information
        return [PSCustomObject]@{
            FriendlyName = $credentialName
            Username = $Username
            CredentialFile = $credentialFile
            Status = "Success"
        }
    }
    catch {
        $errorMessage = "Failed to store credentials: $_"
        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
        Write-Error $errorMessage
    }
}

# Helper function to protect data with encryption
function Protect-Data {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Data,
        
        [Parameter(Mandatory = $false)]
        [byte[]]$Key
    )
    
    if ($Key) {
        # Use AES encryption with provided key
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $Key
        $aes.GenerateIV()
        
        $encryptor = $aes.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
        
        # Combine IV and encrypted data
        $result = $aes.IV + $encryptedData
        return [Convert]::ToBase64String($result)
    } else {
        # Use DPAPI (Windows only)
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
            $dataBytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [Convert]::ToBase64String($encryptedBytes)
    }
}

function Get-ScaleHCOSCredentials {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$FriendlyName,
        
        [Parameter(Mandatory = $false)]
        [string]$Username
    )
    
    # If no name or username is provided, return all credentials
    if ([string]::IsNullOrWhiteSpace($FriendlyName) -and [string]::IsNullOrWhiteSpace($Username)) {
        $results = @{}
        
        # Loop through all credential entries
        foreach ($credentialEntry in $script:Credentials.GetEnumerator()) {
            $credName = $credentialEntry.Key
            $credentialFile = $credentialEntry.Value
            
            try {
                # Check if file exists
                if (Test-Path -Path $credentialFile) {
                    # Read the encrypted credential from file
                    $encryptedCredential = Get-Content -Path $credentialFile
                    
                    # Decrypt the credential data
                    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
                        # For non-Windows PS Core, we need the encryption key file
                        $keyFilePath = Join-Path -Path $script:CredentialFolder -ChildPath "encryption.key"
                        if (-not (Test-Path -Path $keyFilePath)) {
                            Write-Warning "Encryption key file not found for credential '$credName'. Skipping."
                            continue
                        }
                        
                        $keyBytes = Get-Content -Path $keyFilePath -Encoding Byte -Raw
                        $credentialXml = Unprotect-Data -EncryptedData $encryptedCredential -Key $keyBytes
                    } else {
                        # Windows can use DPAPI
                        $credentialXml = Unprotect-Data -EncryptedData $encryptedCredential
                    }
                    
                    # Deserialize the credential object
                    $credential = [System.Management.Automation.PSSerializer]::Deserialize($credentialXml)
                    
                    # Add to results with role as key and credential as value
                    $results[$credName] = [PSCustomObject]@{
                        FriendlyName = $credName
                        Username = $credential.UserName
                        Credential = $credential
                        Path = $credentialFile
                    }
                } else {
                    Write-Warning "Credential file for '$credName' not found at: $credentialFile"
                }
            } catch {
                Write-Warning "Failed to load credential for '$credName': $_"
            }
        }
        
        # Return results as array of custom objects
        return $results.Values | Sort-Object FriendlyName
    }
    # If username is provided, filter by username
    elseif (-not [string]::IsNullOrWhiteSpace($Username)) {
        $matchingCredentials = @()
        
        # Loop through all credential entries
        foreach ($credentialEntry in $script:Credentials.GetEnumerator()) {
            $credName = $credentialEntry.Key
            $credentialFile = $credentialEntry.Value
            
            try {
                # Check if file exists
                if (Test-Path -Path $credentialFile) {
                    # Read the encrypted credential from file
                    $encryptedCredential = Get-Content -Path $credentialFile
                    
                    # Decrypt the credential data
                    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
                        # For non-Windows PS Core, we need the encryption key file
                        $keyFilePath = Join-Path -Path $script:CredentialFolder -ChildPath "encryption.key"
                        if (-not (Test-Path -Path $keyFilePath)) {
                            Write-Warning "Encryption key file not found for credential '$credName'. Skipping."
                            continue
                        }
                        
                        $keyBytes = Get-Content -Path $keyFilePath -Encoding Byte -Raw
                        $credentialXml = Unprotect-Data -EncryptedData $encryptedCredential -Key $keyBytes
                    } else {
                        # Windows can use DPAPI
                        $credentialXml = Unprotect-Data -EncryptedData $encryptedCredential
                    }
                    
                    # Deserialize the credential object
                    $credential = [System.Management.Automation.PSSerializer]::Deserialize($credentialXml)
                    
                    # If username matches, add to results
                    if ($credential.UserName -eq $Username) {
                        # Return the PSCredential object directly for pipeline compatibility
                        $matchingCredentials += $credential
                    }
                }
            } catch {
                Write-Warning "Failed to load credential for '$credName': $_"
            }
        }
        
        # Return the matching credential object(s)
        if ($matchingCredentials.Count -gt 0) {
            return $matchingCredentials
        } else {
            Write-Warning "No credentials found with username '$Username'."
            return $null
        }
    }
    # Original functionality for retrieving a single credential by friendly name
    else {
        $credentialFile = $script:Credentials[$FriendlyName]
        if (-not $credentialFile) {
            $errorMessage = "Credentials with friendly name '$FriendlyName' not found. Please register them first using Register-ScaleHCOSCredentials."
            Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
            throw $errorMessage
        }
        
        # Check if this is a valid file path
        if (-not (Test-Path -Path $credentialFile)) {
            $errorMessage = "Credential file for friendly name '$FriendlyName' not found at: $credentialFile"
            Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
            throw $errorMessage
        }
        
        try {
            # Read the encrypted credential from file
            $encryptedCredential = Get-Content -Path $credentialFile
            
            # Decrypt the credential data
            if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
                # For non-Windows PS Core, we need the encryption key file
                $keyFilePath = Join-Path -Path $script:CredentialFolder -ChildPath "encryption.key"
                if (-not (Test-Path -Path $keyFilePath)) {
                    throw "Encryption key file not found. Cannot decrypt credentials."
                }
                
                $keyBytes = Get-Content -Path $keyFilePath -Encoding Byte -Raw
                $credentialXml = Unprotect-Data -EncryptedData $encryptedCredential -Key $keyBytes
            } else {
                # Windows can use DPAPI
                $credentialXml = Unprotect-Data -EncryptedData $encryptedCredential
            }
            
            # Deserialize the credential object
            $credential = [System.Management.Automation.PSSerializer]::Deserialize($credentialXml)
            
            # Return the PSCredential object directly for pipeline compatibility
            return $credential
        }
        catch {
            $errorMessage = "Failed to decrypt credentials: $_"
            Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
            throw $errorMessage
        }
    }
}
# Helper function to decrypt protected data
function Unprotect-Data {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EncryptedData,
        
        [Parameter(Mandatory = $false)]
        [byte[]]$Key
    )
    
    if ($Key) {
        # Use AES decryption with provided key
        $encryptedBytes = [Convert]::FromBase64String($EncryptedData)
        
        # Extract IV (first 16 bytes) and actual data
        $aes = [System.Security.Cryptography.Aes]::Create()
        $iv = $encryptedBytes[0..15]
        $cipherText = $encryptedBytes[16..($encryptedBytes.Length - 1)]
        
        $aes.Key = $Key
        $aes.IV = $iv
        
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)
        
        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    } else {
        # Use DPAPI (Windows only)
        $encryptedBytes = [Convert]::FromBase64String($EncryptedData)
        $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedBytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    }
}

function Remove-ScaleHCOSCredentials {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $false)]
        [string]$FriendlyName,
        
        [Parameter(Mandatory = $false)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    $script:EnableLogging = $EnableLogging
    
    # Check if criteria were provided
    if ([string]::IsNullOrWhiteSpace($FriendlyName) -and [string]::IsNullOrWhiteSpace($Username)) {
        $errorMessage = "Either -FriendlyName or -Username parameter must be specified."
        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
        Write-Error $errorMessage
        return
    }
    
    # If username is provided, find matching credentials
    if (-not [string]::IsNullOrWhiteSpace($Username)) {
        $matchingCredentials = @()
        
        foreach ($credentialEntry in $script:Credentials.GetEnumerator()) {
            $credName = $credentialEntry.Key
            $credentialFile = $credentialEntry.Value
            
            try {
                if (Test-Path -Path $credentialFile) {
                    $encryptedCredential = Get-Content -Path $credentialFile
                    
                    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
                        $keyFilePath = Join-Path -Path $script:CredentialFolder -ChildPath "encryption.key"
                        if (-not (Test-Path -Path $keyFilePath)) {
                            Write-Warning "Encryption key file not found for credential '$credName'. Skipping."
                            continue
                        }
                        
                        $keyBytes = Get-Content -Path $keyFilePath -Encoding Byte -Raw
                        $credentialXml = Unprotect-Data -EncryptedData $encryptedCredential -Key $keyBytes
                    } else {
                        $credentialXml = Unprotect-Data -EncryptedData $encryptedCredential
                    }
                    
                    $credential = [System.Management.Automation.PSSerializer]::Deserialize($credentialXml)
                    
                    if ($credential.UserName -eq $Username) {
                        $matchingCredentials += $credName
                    }
                }
            } catch {
                Write-Warning "Failed to check credential for username match: $_"
            }
        }
        
        if ($matchingCredentials.Count -eq 0) {
            Write-Warning "No credentials found with username '$Username'."
            return
        }
        
        foreach ($credName in $matchingCredentials) {
            $credentialFile = $script:Credentials[$credName]
            
            if (Test-Path -Path $credentialFile) {
                if ($Force -or $PSCmdlet.ShouldProcess($credentialFile, "Delete credential file for $credName")) {
                    try {
                        Remove-Item -Path $credentialFile -Force -ErrorAction Stop
                        Write-ScaleHCOSLog -Message "Credential file for '$credName' has been deleted." -Level 'Info'
                        
                        # Remove from the in-memory dictionary
                        $script:Credentials.Remove($credName)
                        Write-ScaleHCOSLog -Message "Credentials for '$credName' have been removed from memory." -Level 'Info'
                        Write-Host "Credentials for friendly name '$credName' have been removed successfully." -ForegroundColor Green
                    } catch {
                        $errorMessage = "Failed to delete credential file: $_"
                        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
                        Write-Error $errorMessage
                    }
                }
            }
        }
    } else {
        # Remove credential by friendly name
        $credentialFile = $script:Credentials[$FriendlyName]
        if (-not $credentialFile) {
            $warningMessage = "Credentials for friendly name '$FriendlyName' not found."
            Write-ScaleHCOSLog -Message $warningMessage -Level 'Warning'
            Write-Warning $warningMessage
            return
        }
        
        # Check if the credential file exists
        if (Test-Path -Path $credentialFile) {
            # Remove the file
            if ($Force -or $PSCmdlet.ShouldProcess($credentialFile, "Delete credential file")) {
                try {
                    Remove-Item -Path $credentialFile -Force -ErrorAction Stop
                    Write-ScaleHCOSLog -Message "Credential file for '$FriendlyName' has been deleted." -Level 'Info'
                } catch {
                    $errorMessage = "Failed to delete credential file: $_"
                    Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
                    Write-Error $errorMessage
                    return
                }
            }
        }
        
        # Remove from the in-memory dictionary
        $script:Credentials.Remove($FriendlyName)
        Write-ScaleHCOSLog -Message "Credentials for friendly name '$FriendlyName' have been removed from memory." -Level 'Info'
        Write-Host "Credentials for friendly name '$FriendlyName' have been removed successfully." -ForegroundColor Green
    }
}

function Invoke-ScaleHCOSRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential, 
        
        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = 'GET',
        
        [Parameter(Mandatory = $false)]
        [object]$Body = $null,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AdditionalHeaders = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$Raw,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 300
    )
    
    # Build REST options hashtable
    $restOpts = @{
        Uri = $Uri
        Method = $Method
        Credential = $Credential
        ContentType = 'application/json'
        TimeoutSec = $TimeoutSeconds
    }
    
    # Add headers if specified
    if ($AdditionalHeaders.Count -gt 0) {
        $restOpts.Headers = $AdditionalHeaders
    }
    
    # Add body if specified
    if ($null -ne $Body) {
        if ($Body -is [string]) {
            $restOpts.Body = $Body
        } else {
            $restOpts.Body = $Body | ConvertTo-Json -Depth 10 -Compress
        }
    }
    
    # Handle certificate validation for PowerShell Core
    if ($SkipCertificateCheck -and $PSVersionTable.PSEdition -eq 'Core') {
        $restOpts.SkipCertificateCheck = $true
    }
    
    # Handle certificate validation for Windows PowerShell
    if ($SkipCertificateCheck -and $PSVersionTable.PSEdition -ne 'Core') {
        Write-ScaleHCOSLog -Message "Using certificate validation bypass in Windows PowerShell" -Level 'Warning'
        
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            try {
                Add-Type -TypeDefinition @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@ -ErrorAction SilentlyContinue
            }
            catch {
                Write-Verbose "TrustAllCertsPolicy type already exists or could not be created: $_"
            }
        }
        
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    
    # Log request
    $logMessage = "Sending $Method request to $Uri with timeout of $TimeoutSeconds seconds"
    Write-ScaleHCOSLog -Message $logMessage -Level 'Info'
    Write-Verbose $logMessage
    
    # Direct execution with error handling
    try {
        # Make the direct REST call
        $response = Invoke-RestMethod @restOpts
        
        # Log successful completion
        Write-ScaleHCOSLog -Message "REST request completed successfully" -Level 'Info'
        
        # Return the response
        return $response
    }
    catch {
        $errorMessage = "REST request failed: $_"
        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
        throw $_
    }
}

function Get-ScaleHCOSNodeInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )
    
    try {
        Write-ScaleHCOSLog -Message "Getting node inventory for server: $Server" -Level 'Info'
        
        $ScaleCluster = "https://$Server/rest/v1"
        
        # Get node information
        $params = @{
            Uri = "$ScaleCluster/Node"
            Credential = $Credential  # Use Credential parameter
            Method = 'GET'
        }
        
        if ($SkipCertificateCheck) {
            $params.Add('SkipCertificateCheck', $true)
        }
        
        $NodeInfo = Invoke-ScaleHCOSRequest @params
        
        if ($null -eq $NodeInfo) {
            Write-Warning "No node information returned from $Server"
            return $null
        }
        
        Write-ScaleHCOSLog -Message "Processing inventory data for $(($NodeInfo | Measure-Object).Count) nodes" -Level 'Info'
        
        $NodeInventory = foreach ($Node in $NodeInfo) {
            # Process drive information
            $driveModels = @()
            $driveSerials = @()
            $driveTypes = @()
            $driveCapacities = @()
            $driveUsages = @()
            $driveHealths = @()
            $driveErrors = @()
            $drivePaths = @()
            $driveTemps = @()
            $driveMaxTemps = @()
            
            # Handle multiple drives if present
            if ($Node.drives.Count -gt 0) {
                foreach ($drive in $Node.drives) {
                    # Process drive model by splitting on underscore and removing serial
                    $driveParts = $drive.UUID -split '_'
                    if ($driveParts.Count -gt 1) {
                        $driveModel = ($driveParts[0..($driveParts.Count-2)] -join '_')
                        $driveModels += $driveModel
                    } else {
                        $driveModels += $drive.UUID
                    }
                    
                    $driveSerials += $drive.serialNumber
                    $driveTypes += $drive.type
                    $driveCapacities += $drive.capacityBytes
                    $driveUsages += $drive.usedBytes
                    $driveHealths += $drive.isHealthy
                    $driveErrors += $drive.errorCount
                    $drivePaths += $drive.blockDevicePath
                    $driveTemps += $drive.temperature
                    $driveMaxTemps += $drive.maxTemperature
                }
            }
            
            # Create the custom object with all node properties
            [PSCustomObject]@{
                UUID = $Node.UUID
                "Backplane IP" = $Node.backplaneIP
                "Lan IP" = $Node.lanIP
                configState = $Node.configState  # Status of node configuration
                activeVersion = $Node.activeVersion  # Current running HCOS version
                "Array Capacity (B)" = $Node.capacity  # Total storage capacity available on the node
                "Drive Model" = $driveModels -join '; '
                "Drive Serial" = $driveSerials -join '; '
                "Drive Type" = $driveTypes -join '; '
                "Drive Capacity (B)" = $driveCapacities -join '; '
                "Drive Usage (B)" = $driveUsages -join '; '
                "Drive Health" = $driveHealths -join '; '
                "Drive Errors" = $driveErrors -join '; '
                "Drive Path" = $drivePaths -join '; '
                "Drive Temperature" = $driveTemps -join '; '
                "Drive Recorded Max Temp" = $driveMaxTemps -join '; '
                vips = $Node.vips  # Virtual IPs assigned to this node
                memSize = $Node.memSize
                "CPU Count" = $Node.numCPUs
                CPUhz = $Node.CPUhz  # CPU frequency in Hz
                numNUMANodes = $Node.numNUMANodes  # Number of NUMA nodes in system
                "CPU Sockets" = $Node.numSockets
                "CPU Cores" = $Node.numCores
                "CPU Threads" = $Node.numThreads
                "Network Status" = $Node.networkStatus
                supportsVirtualization = $Node.supportsVirtualization
                virtualizationOnline = $Node.virtualizationOnline
                pairedNodeUUID = $Node.pairedNodeUUID  # UUID of the paired node in HA configuration
                scribeInstanceName = $Node.scribeInstanceName  # Internal system component name
                "Node ID" = $Node.peerID 
                "RAM Slots" = $Node.numSlots
                "System RAM Usage (B)" = $Node.systemMemUsageBytes
                "RAM Usage (%)" = $Node.memUsagePercentage
                "GPUs" = $Node.gpus
                currentDisposition = $Node.currentDisposition
                desiredDisposition = $Node.desiredDisposition
                "CPU Usage (%)" = $Node.cpuUsage
                "Total RAM Usages (B)" = $Node.totalMemUsageBytes
                "Allow VMs to Run" = $Node.allowRunningVMs
            }
        }
        
        return $NodeInventory
    }
    catch {
        $errorMessage = "Failed to retrieve node inventory: $_"
        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
        throw $_
    }
}

function Get-ScaleHCOSVMInventory {
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$Raw,
        
        [Parameter(Mandatory = $false, ParameterSetName='NameFilter')]
        [string]$Name,
        
        [Parameter(Mandatory = $false, ParameterSetName='UUIDFilter')]
        [string]$UUID,
        
        [Parameter(Mandatory = $false, ParameterSetName='NodeFilter')]
        [string]$NodeUUID,
        
        [Parameter(Mandatory = $false, ParameterSetName='TagFilter')]
        [string]$Tag,
        
        [Parameter(Mandatory = $false, ParameterSetName='PowerStateFilter')]
        [ValidateSet("RUNNING", "STOPPED", "STOPPING", "STARTING", "PAUSED", "MIGRATING", "MAINTENANCE")]
        [string]$PowerState
    )
    
    try {
        Write-ScaleHCOSLog -Message "Getting VM inventory for server: $Server" -Level 'Info'
        
        $ScaleCluster = "https://$Server/rest/v1"
        
        # Get VM information
        $params = @{
            Uri = "$ScaleCluster/VirDomain"
            Credential = $Credential
            Method = 'GET'
        }
        
        if ($SkipCertificateCheck) {
            $params.Add('SkipCertificateCheck', $true)
        }
        
        $VMInfo = Invoke-ScaleHCOSRequest @params
        
        if ($null -eq $VMInfo) {
            Write-Warning "No VM information returned from $Server"
            return $null
        }
        
        # Apply filtering based on parameters
        if ($PSCmdlet.ParameterSetName -ne 'Default' -and -not $Raw) {
            Write-ScaleHCOSLog -Message "Filtering VM inventory data using filter: $($PSCmdlet.ParameterSetName)" -Level 'Info'
            
            switch ($PSCmdlet.ParameterSetName) {
                'NameFilter' {
                    $VMInfo = $VMInfo | Where-Object { $_.name -like "*$Name*" }
                    Write-ScaleHCOSLog -Message "Filtered VMs by name pattern '*$Name*'. Found $($VMInfo.Count) matches." -Level 'Info'
                }
                'UUIDFilter' {
                    $VMInfo = $VMInfo | Where-Object { $_.UUID -eq $UUID }
                    Write-ScaleHCOSLog -Message "Filtered VMs by UUID '$UUID'. Found $($VMInfo.Count) matches." -Level 'Info'
                }
                'NodeFilter' {
                    $VMInfo = $VMInfo | Where-Object { $_.nodeUUID -eq $NodeUUID }
                    Write-ScaleHCOSLog -Message "Filtered VMs by Node UUID '$NodeUUID'. Found $($VMInfo.Count) matches." -Level 'Info'
                }
                'TagFilter' {
                    $VMInfo = $VMInfo | Where-Object { $_.tags -contains $Tag }
                    Write-ScaleHCOSLog -Message "Filtered VMs by Tag '$Tag'. Found $($VMInfo.Count) matches." -Level 'Info'
                }
                'PowerStateFilter' {
                    $VMInfo = $VMInfo | Where-Object { $_.state -eq $PowerState }
                    Write-ScaleHCOSLog -Message "Filtered VMs by Power State '$PowerState'. Found $($VMInfo.Count) matches." -Level 'Info'
                }
            }
        }
        
        # Return raw results if requested
        if ($Raw) {
            return $VMInfo
        }
        
        Write-ScaleHCOSLog -Message "Processing VM inventory data for $(($VMInfo | Measure-Object).Count) VMs" -Level 'Info'
        
        # Process the VM information into a more readable format
        $VMInventory = foreach ($VM in $VMInfo) {
            [PSCustomObject]@{
                "VM Name"             = $VM.name
                UUID                  = $VM.UUID
                "Power State"         = $VM.state
                "Desired Power State" = $VM.desiredDisposition
                "Host Node"           = $VM.nodeUUID
                "Description"         = $VM.description
                "Tags"                = if ($VM.tags) { $VM.tags -join "; " } else { $null }
                "Machine Type"        = $VM.machineType
                "Guest Agent State"   = $VM.guestAgentState
                "Memory (MB)"         = $VM.mem
                "CPU Count"           = $VM.numVCPU
                "Boot Order"          = if ($VM.bootDevices) { $VM.bootDevices -join ", " } else { $null }
                "MAC Addresses"       = ($VM.netDevs | ForEach-Object { $_.macAddress }) -join "; "
                "Network Cards"       = ($VM.netDevs | Measure-Object).Count
                "VLANs"               = ($VM.netDevs | ForEach-Object { $_.vlan }) -join ", "
                "Disks"               = ($VM.blockDevs | Measure-Object).Count
            }
        }
        
        return $VMInventory
    }
    catch {
        $errorMessage = "Failed to retrieve VM inventory: $_"
        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
        throw $_
    }
}

function New-ScaleHCOSVM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "VM created via PowerShell module",
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(0.5, 4096)]
        [double]$MemoryGB = 4,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 128)]
        [int]$CPUCount = 4,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65536)]
        [double]$PrimaryDiskSizeGB = 10,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 65536)]
        [double]$SecondaryDiskSizeGB = 0,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("VIRTIO_DISK", "IDE_DISK", "SCSI_DISK")]
        [string]$DiskType = "VIRTIO_DISK",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("WRITETHROUGH", "WRITEBACK", "NONE")]
        [string]$DiskCacheMode = "WRITETHROUGH",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("VIRTIO", "E1000", "RTL8139")]
        [string]$NetworkType = "VIRTIO",
        
        [Parameter(Mandatory = $false)]
        [int[]]$VLAN,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        
        [Parameter(Mandatory = $false)]
        [switch]$AttachGuestToolsISO,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$Wait,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 300
    )
    
    try {
        Write-ScaleHCOSLog -Message "Creating new VM '$Name' on server $Server" -Level 'Info'
        
        # Validate parameters
        if ($Name.Length -lt 1 -or $Name.Length -gt 80) {
            throw "VM name must be between 1 and 80 characters"
        }
        
        # Convert GB values to bytes for the API
        $MemoryBytes = [math]::Round($MemoryGB * 1GB)
        $PrimaryDiskSizeBytes = [math]::Round($PrimaryDiskSizeGB * 1GB)
        $SecondaryDiskSizeBytes = [math]::Round($SecondaryDiskSizeGB * 1GB)
        
        Write-ScaleHCOSLog -Message "Converting $MemoryGB GB to $MemoryBytes bytes for memory allocation" -Level 'Info'
        Write-ScaleHCOSLog -Message "Converting $PrimaryDiskSizeGB GB to $PrimaryDiskSizeBytes bytes for primary disk" -Level 'Info'
        
        # Construct API URL
        $ScaleCluster = "https://$Server/rest/v1"
        
        # Build network devices configuration
        $networkDevices = @()
        
        if ($VLAN -and $VLAN.Count -gt 0) {
            # Create one network device per VLAN
            foreach ($vlanId in $VLAN) {
                $networkDevices += @{
                    type = $NetworkType
                    vlan = $vlanId
                }
                Write-ScaleHCOSLog -Message "Adding network adapter with VLAN $vlanId" -Level 'Info'
            }
        } else {
            # Create a single network device with no VLAN
            $networkDevices += @{
                type = $NetworkType
            }
            Write-ScaleHCOSLog -Message "Adding network adapter with no VLAN tag" -Level 'Info'
        }
        
        # Build VM creation request body
        $vmRequest = @{
            dom = @{
                name = $Name
                description = $Description
                mem = $MemoryBytes
                numVCPU = $CPUCount
                blockDevs = @(
                    @{
                        capacity = $PrimaryDiskSizeBytes
                        type = $DiskType
                        cacheMode = $DiskCacheMode
                    }
                )
                netDevs = $networkDevices
            }
            options = @{}
        }
        
        # Add tags if provided - convert the array to a single comma-separated string
        if ($Tags -and $Tags.Count -gt 0) {
            $tagsString = $Tags -join ','
            Write-ScaleHCOSLog -Message "Adding tags to VM: $tagsString" -Level 'Info'
            $vmRequest.dom.tags = $tagsString
        }
        
        # Add guest tools ISO option if requested
        if ($AttachGuestToolsISO) {
            $vmRequest.options.attachGuestToolsISO = $true
        }
        
        # Step 1: Create the VM
        Write-ScaleHCOSLog -Message "Sending VM creation request for '$Name'" -Level 'Info'
        
        $params = @{
            Uri = "$ScaleCluster/VirDomain"
            Credential = $Credential
            Method = 'POST'
            Body = $vmRequest
        }
        
        if ($SkipCertificateCheck) {
            $params.Add('SkipCertificateCheck', $true)
        }
        
        $result = Invoke-ScaleHCOSRequest @params
        
        if ($null -eq $result -or $null -eq $result.createdUUID) {
            throw "Failed to create VM. No UUID returned from API."
        }
        
        $vmUUID = $result.createdUUID
        $taskTag = $result.taskTag
        
        Write-ScaleHCOSLog -Message "VM '$Name' creation initiated with UUID: $vmUUID" -Level 'Info'
        
        # Wait for VM creation task to complete if Wait is specified
        if ($Wait -and $taskTag) {
            Write-ScaleHCOSLog -Message "Waiting for VM creation task to complete (TaskTag: $taskTag)" -Level 'Info'
            
            $taskComplete = $false
            $startTime = Get-Date
            $endTime = $startTime.AddSeconds($TimeoutSeconds)
            
            while (-not $taskComplete -and (Get-Date) -lt $endTime) {
                $taskParams = @{
                    Uri = "$ScaleCluster/TaskTag/$taskTag"
                    Credential = $Credential
                    Method = 'GET'
                }
                
                if ($SkipCertificateCheck) {
                    $taskParams.Add('SkipCertificateCheck', $true)
                }
                
                $taskInfo = Invoke-ScaleHCOSRequest @taskParams
                
                if ($null -eq $taskInfo) {
                    Write-ScaleHCOSLog -Message "Task $taskTag not found or returned null" -Level 'Warning'
                    break
                }
                
                $status = $taskInfo.state
                
                switch ($status) {
                    "COMPLETE" {
                        Write-ScaleHCOSLog -Message "Task $taskTag completed successfully" -Level 'Info'
                        $taskComplete = $true
                    }
                    "ERROR" {
                        $errorMessage = "Task $taskTag failed with error: $($taskInfo.errorMessage)"
                        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
                        throw $errorMessage
                    }
                    "PENDING" {
                        # Still running, continue waiting
                        Start-Sleep -Seconds 2
                    }
                    "RUNNING" {
                        # Still running, continue waiting
                        Start-Sleep -Seconds 2
                    }
                    default {
                        Write-ScaleHCOSLog -Message "Task $taskTag in unknown state: $status" -Level 'Warning'
                        Start-Sleep -Seconds 2
                    }
                }
            }
            
            if (-not $taskComplete) {
                $errorMessage = "Task $taskTag timed out after $TimeoutSeconds seconds"
                Write-ScaleHCOSLog -Message $errorMessage -Level 'Warning'
                throw $errorMessage
            }
        }
        
        # Step 2: Add secondary disk if specified
        if ($SecondaryDiskSizeGB -gt 0) {
            Write-ScaleHCOSLog -Message "Adding secondary disk of size $SecondaryDiskSizeGB GB to VM $vmUUID" -Level 'Info'
            
            $diskRequest = @{
                virDomainUUID = $vmUUID
                capacity = $SecondaryDiskSizeBytes
                type = $DiskType
                cacheMode = $DiskCacheMode
            }
            
            $diskParams = @{
                Uri = "$ScaleCluster/VirDomainBlockDevice"
                Credential = $Credential
                Method = 'POST'
                Body = $diskRequest
            }
            
            if ($SkipCertificateCheck) {
                $diskParams.Add('SkipCertificateCheck', $true)
            }
            
            $diskResult = Invoke-ScaleHCOSRequest @diskParams
            
            if ($Wait -and $diskResult.taskTag) {
                $diskTaskTag = $diskResult.taskTag
                Write-ScaleHCOSLog -Message "Waiting for secondary disk addition task to complete (TaskTag: $diskTaskTag)" -Level 'Info'
                
                $diskTaskComplete = $false
                $diskStartTime = Get-Date
                $diskEndTime = $diskStartTime.AddSeconds($TimeoutSeconds)
                
                while (-not $diskTaskComplete -and (Get-Date) -lt $diskEndTime) {
                    $diskTaskParams = @{
                        Uri = "$ScaleCluster/TaskTag/$diskTaskTag"
                        Credential = $Credential
                        Method = 'GET'
                    }
                    
                    if ($SkipCertificateCheck) {
                        $diskTaskParams.Add('SkipCertificateCheck', $true)
                    }
                    
                    $diskTaskInfo = Invoke-ScaleHCOSRequest @diskTaskParams
                    
                    if ($null -eq $diskTaskInfo) {
                        Write-ScaleHCOSLog -Message "Disk task $diskTaskTag not found or returned null" -Level 'Warning'
                        break
                    }
                    
                    $diskStatus = $diskTaskInfo.state
                    
                    switch ($diskStatus) {
                        "COMPLETE" {
                            Write-ScaleHCOSLog -Message "Disk task $diskTaskTag completed successfully" -Level 'Info'
                            $diskTaskComplete = $true
                        }
                        "ERROR" {
                            $errorMessage = "Disk task $diskTaskTag failed with error: $($diskTaskInfo.errorMessage)"
                            Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
                            throw $errorMessage
                        }
                        "PENDING" {
                            # Still running, continue waiting
                            Start-Sleep -Seconds 2
                        }
                        "RUNNING" {
                            # Still running, continue waiting
                            Start-Sleep -Seconds 2
                        }
                        default {
                            Write-ScaleHCOSLog -Message "Disk task $diskTaskTag in unknown state: $diskStatus" -Level 'Warning'
                            Start-Sleep -Seconds 2
                        }
                    }
                }
                
                if (-not $diskTaskComplete) {
                    $errorMessage = "Disk task $diskTaskTag timed out after $TimeoutSeconds seconds"
                    Write-ScaleHCOSLog -Message $errorMessage -Level 'Warning'
                    throw $errorMessage
                }
            }
        }
        
        # Return VM details
        $vmDetails = [PSCustomObject]@{
            VMName = $Name
            UUID = $vmUUID
            CPUCount = $CPUCount
            MemoryGB = $MemoryGB
            PrimaryDiskSizeGB = $PrimaryDiskSizeGB
            SecondaryDiskSizeGB = $SecondaryDiskSizeGB
            VLANs = $VLAN
            Tags = $Tags
            NetworkCards = $networkDevices.Count
            CreationTaskTag = $taskTag
            Server = $Server
        }
        
        Write-ScaleHCOSLog -Message "VM creation process completed successfully for VM '$Name' (UUID: $vmUUID)" -Level 'Info'
        return $vmDetails
    }
    catch {
        $errorMessage = "Failed to create VM: $_"
        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
        throw $_
    }
}

function New-ScaleHCOSVMSnapshot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$vmUUID,
        
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,
        
        [Parameter(Mandatory = $false)]
        [string]$SnapshotLabel = "Snapshot created via PowerShell module",
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$Wait,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 300
    )
    
    begin {
        Write-ScaleHCOSLog -Message "Starting VM snapshot creation process" -Level 'Info'
        $ScaleCluster = "https://$Server/rest/v1"
    }
    
    process {
        try {
            Write-ScaleHCOSLog -Message "Creating snapshot for VM with UUID: $vmUUID" -Level 'Info'
            Write-Host "Create VM snapshot"
            
            # Build the request body
            $body = @{
                domainUUID = $vmUUID
                label = $SnapshotLabel
            }
            
            # Set up parameters for Invoke-ScaleHCOSRequest
            $params = @{
                Uri = "$ScaleCluster/VirDomainSnapshot"
                Credential = $Credential
                Method = 'POST'
                Body = $body
                SkipCertificateCheck = $SkipCertificateCheck
            }
            
            # Execute the request using Invoke-ScaleHCOSRequest
            $result = Invoke-ScaleHCOSRequest @params
            
            # Get the snapshot UUID from the result
            $snapUUID = $result.createdUUID
            $taskTag = $result.taskTag
            
            Write-ScaleHCOSLog -Message "Snapshot creation initiated for VM $vmUUID. Snapshot UUID: $snapUUID, TaskTag: $taskTag" -Level 'Info'
            
            # Wait for task to complete if Wait is specified
            if ($Wait -and $taskTag) {
                Write-ScaleHCOSLog -Message "Waiting for snapshot creation task to complete (TaskTag: $taskTag)" -Level 'Info'
                
                Wait-ScaleTask -TaskTag $taskTag -Server $Server -Credential $Credential -TimeoutSeconds $TimeoutSeconds -SkipCertificateCheck:$SkipCertificateCheck
            }
            
            # Return snapshot details
            $snapshotDetails = [PSCustomObject]@{
                VMUUID = $vmUUID
                SnapshotUUID = $snapUUID
                SnapshotLabel = $SnapshotLabel
                TaskTag = $taskTag
                Server = $Server
                CreationTime = Get-Date
            }
            
            Write-ScaleHCOSLog -Message "Snapshot creation process completed for VM $vmUUID" -Level 'Info'
            return $snapshotDetails
        }
        catch {
            $errorMessage = "Failed to create VM snapshot: $_"
            Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
            throw $_
        }
    }
    
    end {
        Write-ScaleHCOSLog -Message "VM snapshot creation process finished" -Level 'Info'
    }
}

function Get-ScaleHCOSLocalUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    try {
        # Define the parameters for the Invoke-ScaleHCOSRequest function
        $Params = @{
            Uri                 = "https://$Server/rest/v1/User"
            Credential          = $Credential
            SkipCertificateCheck = $SkipCertificateCheck
        }

        # Execute the request
        $response = Invoke-ScaleHCOSRequest @Params

        # Return the response as an object
        return $response
    }
    catch {
        # Handle any errors that occur during execution
        $errorMessage = "Failed to retrieve local user information: $_"
        Write-Error $errorMessage
        throw $errorMessage
    }
}

function Get-ScaleHCOSLocalUserRole {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    try {
        # Define the parameters for the Invoke-ScaleHCOSRequest function
        $Params = @{
            Uri                 = "https://$Server/rest/v1/Role"
            Credential          = $Credential
            SkipCertificateCheck = $SkipCertificateCheck
        }

        # Execute the request
        $response = Invoke-ScaleHCOSRequest @Params

        # Return the response as an object
        return $response
    }
    catch {
        # Handle any errors that occur during execution
        $errorMessage = "Failed to retrieve local user role information: $_"
        Write-Error $errorMessage
        throw $errorMessage
    }
}

function Get-ScaleHCOSRegistration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    try {
        # Define the parameters for the Invoke-ScaleHCOSRequest function
        $Params = @{
            Uri                 = "https://$Server/rest/v1/Registration"
            Credential          = $Credential
            SkipCertificateCheck = $SkipCertificateCheck
        }

        # Execute the request
        $response = Invoke-ScaleHCOSRequest @Params
        [xml]$xmlResponse = $response.clusterData
        # Process the response and create a PSCustomObject for readability
        $formattedResult = [PSCustomObject]@{
            UUID                = $response.uuid
            CompanyName         = $response.companyName
            Contact             = $response.contact
            Phone               = $response.phone
            Email               = $response.email
            ClusterID           = $response.clusterID
            ClusterName         = $xmlresponse.registration.clusterName
            ClusterVersion      = $xmlresponse.registration.version
<#
            NodeInfo            = $response.clusterData.registration.nodeInfo.node | ForEach-Object {
                [PSCustomObject]@{
                    Manufacturer       = $_.'system-manufacturer'
                    ProductName        = $_.'system-product-name'
                    SerialNumber       = $_.'system-serial-number'
                    UUID               = $_.'system-uuid'
                    ProcessorFamily    = $_.'processor-family'
                    ProcessorFrequency = $_.'processor-frequency'
                    ProcessorVersion   = $_.'processor-version'
                    RAMSize            = $_.'memSize'
                }
            }#> # enumerate each node and list as node 1, node 2, etc
            "Contact Name"             = $xmlResponse.registration.contactList.item.name
            "Contact Phone"            = $xmlResponse.registration.contactList.item.phone
            "Contact Email"            = $xmlResponse.registration.contactList.item.email
            ClusterDataHash     = $response.clusterDataHash
            ClusterDataHashAccepted = $response.clusterDataHashAccepted
        }

        # Return the formatted result
        return $formattedResult
    }
    catch {
        # Handle any errors that occur during execution
        $errorMessage = "Failed to retrieve registration information: $_"
        Write-Error $errorMessage
        throw $errorMessage
    }
}

try {
    Initialize-ScaleHCOSEnvironment
} catch {
    Write-Warning "Module initialization encountered an issue: $_"
    Write-Warning "Some functionality may be limited. Run Initialize-ScaleHCOSEnvironment manually with administrator privileges."
}

# Export module members - now including all functions
Export-ModuleMember -Function Get-ScaleHCOSRegistration, Get-ScaleHCOSLocalUserRole, Get-ScaleHCOSLocalUser, Register-ScaleHCOSCredentials, Get-ScaleHCOSCredentials, Remove-ScaleHCOSCredentials, Invoke-ScaleHCOSRequest, Get-ScaleHCOSNodeInventory, New-ScaleHCOSVMSnapshot, Get-ScaleHCOSVMInventory, New-ScaleHCOSVM