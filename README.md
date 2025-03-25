# POSH-ScaleHCOSAPI
Powershell Module to interact with Scale Computing's HCOS API

# Overview
The ScaleHCOSAPI PowerShell module provides a secure and user-friendly interface for interacting with Scale Computing's Hypercore Operating System (HCOS) RESTful API. This module enables administrators to automate common management tasks for Scale Computing HC3 clusters.

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
# Register a new credential set
Register-ScaleHCOSCredentials -Username "admin" -FriendlyName "HC3-Cluster1"

# Retrieve stored credentials
$creds = Get-ScaleHCOSCredentials -FriendlyName "HC3-Cluster1"

# Remove stored credentials
Remove-ScaleHCOSCredentials -FriendlyName "HC3-Cluster1"
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