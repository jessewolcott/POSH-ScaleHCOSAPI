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
        [string]$Role,

        [Parameter(Mandatory = $false)]
        [string]$EncryptionKeyFile,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    # Set logging state
    $script:EnableLogging = $EnableLogging
    
    # Initialize environment
    Initialize-ScaleHCOSEnvironment
    
    # Either use provided Role or prompt for it
    if ([string]::IsNullOrWhiteSpace($Role)) {
        $roleName = Read-Host -Prompt "Enter a name for this user. You can also add descriptors. (e.g., OrgAdmin, ReadOnly)"
    } else {
        $roleName = $Role
        Write-ScaleHCOSLog -Message "Using provided role name: $roleName" -Level 'Info'
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
        $credentialFile = Join-Path -Path $script:CredentialFolder -ChildPath "$roleName.cred"
        $encryptedCredential | Set-Content -Path $credentialFile -Force
        
        Write-ScaleHCOSLog -Message "Credentials stored successfully for role: $roleName" -Level 'Info'
        Write-Host "Credentials stored successfully for role: $roleName" -ForegroundColor Green
        
        # Add to the in-memory credentials dictionary
        $script:Credentials[$roleName] = $credentialFile
        
        # Return success information
        return [PSCustomObject]@{
            Role = $roleName
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
        [string]$Name
    )
    
    # If no name is provided, return all credentials
    if ([string]::IsNullOrWhiteSpace($Name)) {
        $results = @{}
        
        # Loop through all credential entries
        foreach ($credentialEntry in $script:Credentials.GetEnumerator()) {
            $roleName = $credentialEntry.Key
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
                            Write-Warning "Encryption key file not found for role '$roleName'. Skipping."
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
                    $results[$roleName] = [PSCustomObject]@{
                        Role = $roleName
                        Username = $credential.UserName
                        Credential = $credential
                        Path = $credentialFile
                    }
                } else {
                    Write-Warning "Credential file for role '$roleName' not found at: $credentialFile"
                }
            } catch {
                Write-Warning "Failed to load credential for role '$roleName': $_"
            }
        }
        
        # Return results as array of custom objects
        return $results.Values | Sort-Object Role
    }
    else {
        # Original functionality for retrieving a single credential
        $credentialFile = $script:Credentials[$Name]
        if (-not $credentialFile) {
            $errorMessage = "Credentials for role '$Name' not found. Please register them first using Register-ScaleCredentials."
            Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
            throw $errorMessage
        }
        
        # Check if this is a valid file path
        if (-not (Test-Path -Path $credentialFile)) {
            $errorMessage = "Credential file for role '$Name' not found at: $credentialFile"
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
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Role,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    $script:EnableLogging = $EnableLogging
    
    # Use Role parameter if provided, otherwise use Name
    $credentialName = if (-not [string]::IsNullOrWhiteSpace($Role)) { $Role } else { $Name }
    
    # Check if a credential name was provided
    if ([string]::IsNullOrWhiteSpace($credentialName)) {
        $errorMessage = "Either -Name or -Role parameter must be specified."
        Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
        Write-Error $errorMessage
        return
    }
    
    $credentialFile = $script:Credentials[$credentialName]
    if (-not $credentialFile) {
        $warningMessage = "Credentials for role '$credentialName' not found."
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
                Write-ScaleHCOSLog -Message "Credential file for '$credentialName' has been deleted." -Level 'Info'
            } catch {
                $errorMessage = "Failed to delete credential file: $_"
                Write-ScaleHCOSLog -Message $errorMessage -Level 'Error'
                Write-Error $errorMessage
                return
            }
        }
    }
    
    # Remove from the in-memory dictionary
    $script:Credentials.Remove($credentialName)
    Write-ScaleHCOSLog -Message "Credentials for role '$credentialName' have been removed from memory." -Level 'Info'
    Write-Host "Credentials for role '$credentialName' have been removed successfully." -ForegroundColor Green
}

function Invoke-ScaleHCOSRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $true)]
        [string]$Role,
        
        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = 'GET',
        
        [Parameter(Mandatory = $false)]
        [object]$Body = $null,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AdditionalHeaders = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$Raw,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )
    
    try {
        $credential = Get-ScaleHCOSCredentials -Name $Role
        
        # Build REST options hashtable
        $restOpts = @{
            Uri = $Uri
            Method = $Method
            Credential = $credential
            ContentType = 'application/json'
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
        
        # Handle certificate validation based on PowerShell version
        if ($SkipCertificateCheck) {
            if ($PSVersionTable.PSEdition -eq 'Core') {
                # PowerShell Core has SkipCertificateCheck parameter
                $restOpts.SkipCertificateCheck = $true
            } else {
                # Windows PowerShell requires callback
                Write-ScaleHCOSLog -Message "Using certificate validation bypass in Windows PowerShell" -Level 'Warning'
                
                # Create callback to ignore certificate validation
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
"@
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                
                # Set security protocol to TLS 1.2
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            }
        }
        
        # Log request (excluding sensitive information)
        $logMessage = "Sending $Method request to $Uri"
        Write-ScaleHCOSLog -Message $logMessage -Level 'Info'
        
        # Make the REST call
        $response = Invoke-RestMethod @restOpts
        
        # Return raw response or process it
        if ($Raw) {
            return $response
        } else {
            return $response
        }
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
        [string]$Role = "Administrator",
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )
    
    try {
        Write-ScaleHCOSLog -Message "Getting node inventory for server: $Server" -Level 'Info'
        
        $ScaleCluster = "https://$Server/rest/v1"
        
        # Get node information
        $params = @{
            Uri = "$ScaleCluster/Node"
            Role = $Role
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
try {
    Initialize-ScaleHCOSEnvironment
} catch {
    Write-Warning "Module initialization encountered an issue: $_"
    Write-Warning "Some functionality may be limited. Run Initialize-ScaleHCOSEnvironment manually with administrator privileges."
}

# Export module members - now including all functions
Export-ModuleMember -Function Register-ScaleHCOSCredentials, Get-ScaleHCOSCredentials, Remove-ScaleHCOSCredentials, Invoke-ScaleHCOSRequest, Get-ScaleHCOSNodeInventory