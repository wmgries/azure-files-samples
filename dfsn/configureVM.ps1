param(
    [string]$EncodedNamespaces,
    [string]$ServerName,
    [string]$OdjBlob,
    [string]$TempUser,
    [switch]$SkipUserDisable
)

# Import cmdlets shared between ARM templates
Import-Module .\AzureFilesArmUtilities.psm1

# Install DFS-N Windows Server Role
Install-WindowsFeature `
        -Name "FS-DFS-Namespace" | `
    Out-Null

# Domain join server
$path = Get-Location | Select-Object -ExpandProperty Path
$dnsForwarderOdj = [System.IO.Path]::Combine($path, "dfsn.odj")
$djOutput = [System.IO.Path]::Combine($path, "djOutput.txt")

Write-OdjBlob -OdjBlob $OdjBlob -Path $dnsForwarderOdj
Join-WindowsMachine `
    -OdjBlobPath $dnsForwarderOdj `
    -WindowsPath $env:windir `
    -JoinOutputPath $djOutput

# Set registry keys required for root consolidation
New-RegistryItem `
        -ParentPath "HKLM:\SYSTEM\CurrentControlSet\Services" `
        -Name "Dfs"

New-RegistryItem `
        -ParentPath "HKLM:\SYSTEM\CurrentControlSet\Services\Dfs" `
        -Name "Parameters"

New-RegistryItem `
        -ParentPath "HKLM:\SYSTEM\CurrentControlSet\Services\Dfs\Parameters" `
        -Name "Replicated"

New-RegistryItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dfs\Parameters\Replicated" `
        -Name "ServerConsolidationRetry" `
        -Value 1

# Create DFS-N namespaces
$namespaces = ConvertFrom-EncodedJson -String $EncodedNamespaces
foreach($namespace in $namespaces) {
    New-Item `
            -Path "C:\DFSRoots\#$($namespace.rootName)" `
            -ItemType Directory | `
        Out-Null

    New-SmbShare `
            -Path "C:\DFSRoots\#$($namespace.rootName)" `
            -Name "#$($namespace.rootName)" | `
        Out-Null

    $serverPathUNC = "\\$ServerName\#$($namespace.rootName)"
    
    New-DfsnRoot `
            -Path $serverPathUNC `
            -TargetPath $serverPathUNC `
            -Type Standalone | `
        Out-Null
    
    foreach($share in $namespace.shares) {
        $sharePathUNC = "$serverPathUNC\$($share.shareName)"

        foreach($folderTarget in $share.folderTargets) {
            $dfsShare = Get-DfsnFolder -Path "$serverPathUNC\*" | `
                Where-Object { $_.Path -eq $sharePathUNC }
            
            if ($null -eq $dfsShare) {
                New-DfsnFolder `
                        -Path $sharePathUNC `
                        -TargetPath $folderTarget.targetUNC | `
                    Out-Null
            } else {
                New-DfsnFolderTarget `
                        -Path $sharePathUNC `
                        -TargetPath $folderTarget.targetUNC | `
                    Out-Null
            }
        }
    }
}

# Disable temp user - login through the domain
if (!$SkipUserDisable) {
    Disable-LocalUser -Name $TempUser
}