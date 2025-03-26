# POSH-ScaleHCOSAPI
Powershell Module to interact with Scale Computing's HCOS API

# Overview
The ScaleHCOSAPI PowerShell module provides a secure and user-friendly interface for interacting with Scale Computing's Hypercore Operating System (HCOS) RESTful API. This module enables administrators to automate common management tasks for Scale Computing HC3 clusters.

The reference doc for this can be found on your cluster at (https://{{ server }}/rest/v1/docs/). 

# Features
* Secure credential management for Scale Computing environments
* Comprehensive logging system for troubleshooting and auditing
* Certificate validation options for secure environments
* Node and virtual machine inventory management
* Virtual machine creation and management capabilities
* VM snapshot management
* Cross-platform support (Windows PowerShell and PowerShell Core)

# Installation
Download the module files
Extract to a folder in your PowerShell module path (e.g., $env:USERPROFILE\Documents\WindowsPowerShell\Modules\ScaleHCOSAPI)
Import the module:
```powershell
Import-Module .\SCALEHCOSAPI.psm1 
```

# Getting Started
## Credential Management
The module provides secure credential storage for your Scale Computing environments:
```powershell
# Register a new credential set - Use -Password to set up a credential file for later use. 
Register-ScaleHCOSCredentials -Username "admin" -FriendlyName "Administrator"

# Retrieve stored credentials
$creds = Get-ScaleHCOSCredentials -FriendlyName "Administrator"

# Remove stored credentials
Remove-ScaleHCOSCredentials -FriendlyName "Administrator"
```

## Basic Usage Examples
``` powershell
# Connect to a Scale HC3 cluster and get node inventory
$nodeInventory = Get-ScaleHCOSNodeInventory -Server "cluster.example.com" -Credential $creds

# List all VMs in the cluster
$vms = Get-ScaleHCOSVMInventory -Server "cluster.example.com" -Credential $creds

# Filter VMs by name
$filteredVMs = Get-ScaleHCOSVMInventory -Server "cluster.example.com" -Credential $creds -Name "web-server"

# Create a new VM
$newVM = New-ScaleHCOSVM -Server "cluster.example.com" -Credential $creds -Name "test-vm" -MemoryGB 8 -CPUCount 4 -PrimaryDiskSizeGB 50 -VLAN 10,20 -Tags "test", "development"

# Create a VM snapshot
$snapshot = New-ScaleHCOSVMSnapshot -Server "cluster.example.com" -Credential $creds -vmUUID "12345-abcde" -SnapshotLabel "Pre-update backup"

# Create snapshots for all VMs with a specific tag using pipeline
Get-ScaleHCOSVMInventory -Server "cluster.example.com" -Credential $creds | 
    Where-Object { $_.Tags -match "production" } | 
    ForEach-Object { $_.UUID } | 
    New-ScaleHCOSVMSnapshot -Server "cluster.example.com" -Credential $creds -SnapshotLabel "Automated backup"
```

## Advanced Usage Examples

### Create a VM with big splat for options

```powershell

$Credential = Get-ScaleHCOSCredentials -FriendlyName "Administrator"
$Server = "cluster.example.com"

$vmParams = @{
    # Required parameters
    Name                 = "TEST VM2"                             # Name of the new virtual machine
        
    # VM specifications
    Description          = "Production VM created via PowerShell" # VM description (default: "VM created via PowerShell module")
    tags                 = "LAB","WIN11","TPM Machines"           # Comma-separated list of tags (default: none)
    MemoryGB             = 8                                      # Memory allocation in GB (default: 4)
    CPUCount             = 4                                      # Number of virtual CPUs (default: 4)
    
    # Disk configuration
    PrimaryDiskSizeGB    = 80                                 # Size of the primary disk in GB (default: 10)
    SecondaryDiskSizeGB  = 200                                # Size of optional secondary disk in GB (default: 0)
    DiskType             = "VIRTIO_DISK"                      # Type of disk to create: VIRTIO_DISK, IDE_DISK, or SCSI_DISK (default: VIRTIO_DISK)
    DiskCacheMode        = "WRITETHROUGH"                     # Disk caching mode: WRITETHROUGH, WRITEBACK, or NONE (default: WRITETHROUGH)
    
    # Network configuration
    NetworkType          = "VIRTIO"                           # Network adapter type: VIRTIO, E1000, or RTL8139 (default: VIRTIO)
    VLAN                 = @(5,20)                            # List of VLAN IDs as array (default: none)

    # Disk Options
    # AttachGuestToolsISO  = $true                            # Whether to attach guest tools ISO (default: $false) - NOT YET IMPLEMENTED
    # Bootable Drive       =                                  # Select boot device - NOT YET IMPLEMENTED

    # Connection options
    SkipCertificateCheck = $true                              # Skip certificate validation for HTTPS connection (default: $false)
    
    # Task management
    Wait                 = $true                              # Wait for VM creation tasks to complete (default: $false)
    TimeoutSeconds       = 600                                # Timeout for task completion in seconds (default: 300)
}
# Call the function using splatting
$newVM = New-ScaleHCOSVM @vmParams -Credential ($Credential) -Server $Server
$newVM
```

### Get a VM Name and make a snapshot
Use `Get-ScaleHCOSVMInventory` to find a VM's UUID by friendly name and pass the UUID to the Snapshot function.

```powershell
$VMtoSnap = (Get-ScaleHCOSVMInventory -Server $Server -Credential $Credential  -Name "SiteController_Store102").UUID

New-ScaleHCOSVMSnapshot -Server $Server -Credential $Credential -vmUUID $VMtoSnap -SnapshotLabel "Test Snap"
```

# Core Functions
| Function | Description |
| --- |--- |
| Register-ScaleHCOSCredentials	| Securely stores credentials for Scale Computing environments |
| Get-ScaleHCOSCredentials	| Retrieves stored credentials by friendly name or username |
| Remove-ScaleHCOSCredentials | Removes stored credentials from the system |
| Invoke-ScaleHCOSRequest | Core function for making API calls to Scale HC3 clusters |
| Get-ScaleHCOSNodeInventory | Retrieves detailed information about nodes in a Scale cluster |
| Get-ScaleHCOSVMInventory | Lists and filters virtual machines in a Scale cluster |
| New-ScaleHCOSVM | Creates a new virtual machine with specified configuration |
| New-ScaleHCOSVMSnapshot | Creates a snapshot of a virtual machine |
| Get-ScaleHCOSLocalUser| Retrieves local users in a Scale cluster |
| Get-ScaleHCOSLocalUserRole | Retrieves local user roles in a Scale cluster |
| Get-ScaleHCOSRegistration | Retrieves registration information in a Scale cluster |

## Advanced Usage
### Handling Self-Signed Certificates
For environments with self-signed certificates, use the -SkipCertificateCheck parameter:
```powershell
$vms = Get-ScaleHCOSVMInventory -Server "cluster.example.com" -Credential $creds -SkipCertificateCheck
```
## Pipeline Support
Many functions support pipeline input for batch operations:

```powershell
# Create snapshots for all running VMs
Get-ScaleHCOSVMInventory -Server "cluster.example.com" -Credential $creds -PowerState "RUNNING" | 
    ForEach-Object { $_.UUID } | 
    New-ScaleHCOSVMSnapshot -Server "cluster.example.com" -Credential $creds
```

# Troubleshooting
The module includes built-in logging functionality. Logs are stored in the Logs directory within the module folder. If you encounter issues, check these logs for detailed information about API interactions and errors.

# Requirements
* PowerShell 5.1 or PowerShell Core 6.0+
* Network connectivity to Scale Computing HC3 clusters
* Appropriate user permissions on the Scale Computing platform

# Todo List
* There are so, so many features missing and workflows missing. 
* Mac OS / Linux testing
* Build AlertEmailTarget
* Build AlertSMTPConfig
* Build AlertSyslogTarget
* Build Certificate
* Build Cluster
* Build ClusterRegistrationData - This is in /Registration so maybe we don't care about this
* Build Condition
* Build default - ping, login, logout
* Build DNSConfig
* Build Drive
* Build GPU
* Build GPUProfile
* Build ISO
* Build MonitoringConfig
* Build Node
* Build NucleusKey
* Build OIDCConfig
* Build Registration - Still need to do Post, Patch, Delete
* Build RemoteClusterConnection
* Build Role
* Build TimeSource
* Build TimeZone
* Build Update
* Build User - Still need to do Post, Patch, Delete
* Build VirDomain - Still have a TON of work to do to make this good
* Build VirDomainBlockDevice
* Build VirDomainNetDevice
* Build VirDomainReplication
* Build VirDomainSnapshot
* Build VirDomainSnapshotSchedule
* Build VirDomainStats
* Build VirtualDisk

