using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Management.Automation

class PSSessionElevationRequiredException : Exception { }

class PSSessionHybridManagementVersionMismatchException : Exception {
    [Version]$LocalVersion
    [Version]$RemoteVersion

    PSSessionHybridManagementVersionMismatchException(
        [Version]$localVersion, 
        [Version]$remoteVersion
    ) {
        $this.LocalVersion = $localVersion
        $this.RemoteVersion = $remoteVersion
    }
}

class AzureLoginRequiredException : Exception { }

class DnsForwardingRule {
    [string]$DomainName
    [bool]$AzureResource
    [ISet[string]]$MasterServers

    hidden Init(
        [string]$domainName, 
        [bool]$azureResource, 
        [ISet[string]]$masterServers
    ) {
        $this.DomainName = $domainName
        $this.AzureResource = $azureResource
        $this.MasterServers = $masterServers
    }

    hidden Init(
        [string]$domainName,
        [bool]$azureResource,
        [IEnumerable[string]]$masterServers 
    ) {
        $this.DomainName = $domainName
        $this.AzureResource = $azureResource
        $this.MasterServers = [HashSet[string]]::new($masterServers)
    }

    hidden Init(
        [string]$domainName,
        [bool]$azureResource,
        [IEnumerable]$masterServers
    ) {
        $this.DomainName = $domainName
        $this.AzureResource = $azureResource
        $this.MasterServers = [HashSet[string]]::new()

        foreach($item in $masterServers) {
            $this.MasterServers.Add($item.ToString()) | Out-Null
        }
    }

    DnsForwardingRule(
        [string]$domainName, 
        [bool]$azureResource, 
        [ISet[string]]$masterServers
    ) {
        $this.Init($domainName, $azureResource, $masterServers)
    }

    DnsForwardingRule(
        [string]$domainName,
        [bool]$azureResource,
        [IEnumerable[string]]$masterServers 
    ) {
        $this.Init($domainName, $azureResource, $masterServers)
    }

    DnsForwardingRule(
        [string]$domainName,
        [bool]$azureResource,
        [IEnumerable]$masterServers
    ) {
        $this.Init($domainName, $azureResource, $masterServers)
    }

    DnsForwardingRule([PSCustomObject]$customObject) {
        $properties = $customObject | `
            Get-Member | `
            Where-Object { $_.MemberType -eq "NoteProperty" }

        $hasDomainName = $properties | `
            Where-Object { $_.Name -eq "DomainName" }
        if ($null -eq $hasDomainName) {
            throw [ArgumentException]::new(
                "Deserialized customObject does not have the DomainName property.", "customObject")
        }
        
        $hasAzureResource = $properties | `
            Where-Object { $_.Name -eq "AzureResource" }
        if ($null -eq $hasAzureResource) {
            throw [ArgumentException]::new(
                "Deserialized customObject does not have the AzureResource property.", "customObject")
        }

        $hasMasterServers = $properties | `
            Where-Object { $_.Name -eq "MasterServers" }
        if ($null -eq $hasMasterServers) {
            throw [ArgumentException]::new(
                "Deserialized customObject does not have the MasterServers property.", "customObject")
        }

        if ($customObject.MasterServers -isnot [object[]]) {
            throw [ArgumentException]::new(
                "Deserialized MasterServers is not an array.", "customObject")
        }

        $this.Init(
            $customObject.DomainName, 
            $customObject.AzureResource, 
            $customObject.MasterServers)
    }

    [int] GetHashCode() {
        return $this.DomainName.GetHashCode()
    }

    [bool] Equals([object]$obj) {
        return $obj.GetHashCode() -eq $this.GetHashCode()
    }
}

class DnsForwardingRuleSet {
    [ISet[DnsForwardingRule]]$DnsForwardingRules

    DnsForwardingRuleSet() {
        $this.DnsForwardingRules = [HashSet[DnsForwardingRule]]::new()
    }

    DnsForwardingRuleSet([IEnumerable]$dnsForwardingRules) {
        $this.DnsForwardingRules = [HashSet[DnsForwardingRule]]::new()

        foreach($rule in $dnsForwardingRules) {
            $this.DnsForwardingRules.Add($rule) | Out-Null
        }
    }

    DnsForwardingRuleSet([PSCustomObject]$customObject) {
        $properties = $customObject | `
            Get-Member | `
            Where-Object { $_.MemberType -eq "NoteProperty" }
        
        $hasDnsForwardingRules = $properties | `
            Where-Object { $_.Name -eq "DnsForwardingRules" }
        if ($null -eq $hasDnsForwardingRules) {
            throw [ArgumentException]::new(
                "Deserialized customObject does not have the DnsForwardingRules property.", "customObject")
        }

        if ($customObject.DnsForwardingRules -isnot [object[]]) {
            throw [ArgumentException]::new(
                "Deserialized DnsForwardingRules is not an array.", "customObject")
        }

        $this.DnsForwardingRules = [HashSet[DnsForwardingRule]]::new()
        foreach($rule in $customObject.DnsForwardingRules) {
            $this.DnsForwardingRules.Add([DnsForwardingRule]::new($rule)) | Out-Null
        }
    }
}

# class CollectionsDeserializer : PSTypeConverter {
#     [bool] CanConvertFrom([object]$sourceValue, [Type]$destinationType) {
#         $matches = $sourceValue.PSTypeNames | Where-Object { $_ -like "System.Collections.Generic.HashSet`1[[System.String*]]" }
#         return $null -ne $matches
#     }

#     [bool] CanConvertTo([object]$sourceValue, [Type]$destinationType) {
#         return $true
#     }
    
#     [object] ConvertFrom(
#         [object]$sourceValue, 
#         [Type]$destinationType, 
#         [IFormatProvider]$formatProvider, 
#         [bool]$ignoreCase
#     ) {
#         return [IEnumerable]$sourceValue
#     }

#     [object] ConvertTo(
#         [object]$sourceValue, 
#         [Type]$destinationType, 
#         [IFormatProvider]$formatProvider, 
#         [bool]$ignoreCase
#     ) {
#         throw [System.NotImplementedException]::new()
#     }
# }

# class DnsForwardingRuleSetDeserializer : PSTypeConverter {
#     [bool] CanConvertFrom([object]$sourceValue, [Type]$destinationType) {
#         return ([PSObject]$sourceValue).PSTypeNames.Contains("Deserialized.DnsForwardingRuleSet")
#     }

#     [bool] ConvertFrom(
#         [object]$sourceValue, 
#         [Type]$destinationType, 
#         [IFormatProvider]$formatProvider, 
#         [bool]$ignoreCase
#     ) {
#         $psObj = [PSObject]$sourceValue
#         return [DnsForwardingRuleSet]
#     }
# }

enum OSFeatureKind {
    WindowsServerFeature
    WindowsClientCapability
    WindowsClientOptionalFeature
}

class OSFeature {
    [string]$Name
    [string]$InternalOSName 
    [string]$Version 
    [bool]$Installed
    [OSFeatureKind]$FeatureKind

    OSFeature(
        [string]$name,
        [string]$internalOSName,
        [string]$version,
        [bool]$installed,
        [OSFeatureKind]$featureKind
    ) {
        $this.Name = $name
        $this.InternalOSName = $internalOSName
        $this.Version = $version
        $this.Installed = $installed
        $this.FeatureKind = $featureKind
    }
}

$azurePrivateDnsIp = "168.63.129.16"
$DnsForwarderTemplate = "https://raw.githubusercontent.com/wmgries/azure-files-samples/HybridManagement/dns-forwarder/azuredeploy.json"

function Resolve-PathRelative {
    [CmdletBinding()]

    param(
        [Parameter(
            Mandatory=$true, 
            Position=0)]
        [string[]]$PathParts
    )

    return [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($PathParts))
}

function Get-CurrentModule {
    [CmdletBinding()]
    param()

    $ModuleInfo = Get-Module | Where-Object { $_.Path -eq $PSCommandPath }
    if ($null -eq $moduleInfo) {
        throw [System.IO.FileNotFoundException]::new(
            "Could not find a loaded module with the indicated filename.", $PSCommandPath)
    }

    return $ModuleInfo
}

function Get-ModuleFiles {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
        [System.Management.Automation.PSModuleInfo]$ModuleInfo
    )

    process {
        $moduleFiles = [System.Collections.Generic.HashSet[string]]::new()

        if (!$PSBoundParameters.ContainsKey("ModuleInfo")) {
            $ModuleInfo = Get-CurrentModule
        }
    
        $manifestPath = Resolve-PathRelative `
                -PathParts $ModuleInfo.ModuleBase, "$($moduleInfo.Name).psd1"
        
        if (!(Test-Path -Path $manifestPath)) {
            throw [System.IO.FileNotFoundException]::new(
                "Could not find a module manifest with the indicated filename", $manifestPath)
        }
        
        try {
            $manifest = Import-PowerShellDataFile -Path $manifestPath
        } catch {
            throw [System.IO.FileNotFoundException]::new(
                "File matching name of manifest found, but does not contain module manifest.", $manifestPath)
        }
    
        $moduleFiles.Add($manifestPath) | Out-Null
        $moduleFiles.Add((Resolve-PathRelative `
                -PathParts $ModuleInfo.ModuleBase, $manifest.RootModule)) | `
            Out-Null
        
        if ($null -ne $manifest.NestedModules) {
            foreach($nestedModule in $manifest.NestedModules) {
                $moduleFiles.Add((Resolve-PathRelative `
                        -PathParts $ModuleInfo.ModuleBase, $nestedModule)) | `
                    Out-Null
            }
        }
        
        if ($null -ne $manifest.FormatsToProcess) {
            foreach($format in $manifest.FormatsToProcess) {
                $moduleFiles.Add((Resolve-PathRelative `
                        -PathParts $ModuleInfo.ModuleBase, $format)) | `
                    Out-Null
            }
        }
    
        if ($null -ne $manifest.RequiredAssemblies) {
            foreach($assembly in $manifest.RequiredAssemblies) {
                $moduleFiles.Add((Resolve-PathRelative `
                        -PathParts $ModuleInfo.ModuleBase, $assembly)) | `
                    Out-Null
            }
        }

        return $moduleFiles
    }
}

function Copy-RemoteModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $moduleInfo = Get-CurrentModule
    $moduleFiles = Get-ModuleFiles | `
        Get-Item | `
        Select-Object `
            @{ Name = "Name"; Expression = { $_.Name } }, 
            @{ Name = "Content"; Expression = { (Get-Content -Path $_.FullName) } }

    Invoke-Command `
            -Session $Session  `
            -ArgumentList $moduleInfo.Name, $moduleInfo.Version.ToString(), $moduleFiles `
            -ScriptBlock {
                $moduleName = $args[0]
                $moduleVersion = $args[1]
                $moduleFiles = $args[2]

                $psModPath = $env:PSModulePath.Split(";")[0]
                if (!(Test-Path -Path $psModPath)) {
                    New-Item -Path $psModPath -ItemType Directory | Out-Null
                }

                $modulePath = [System.IO.Path]::Combine(
                    $psModPath, $moduleName, $moduleVersion)
                if (!(Test-Path -Path $modulePath)) {
                    New-Item -Path $modulePath -ItemType Directory | Out-Null
                }

                foreach($moduleFile in $moduleFiles) {
                    $filePath = [System.IO.Path]::Combine($modulePath, $moduleFile.Name)
                    $fileContent = $moduleFile.Content
                    Set-Content -Path $filePath -Value $fileContent
                }
            }
}

$sessionDictionary = [System.Collections.Generic.Dictionary[System.Tuple[string, string], System.Management.Automation.Runspaces.PSSession]]::new()
function Initialize-RemoteSession {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ParameterSetName="Copy-Session")]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory=$true, ParameterSetName="Copy-ComputerName")]
        [string]$ComputerName,

        [Parameter(Mandatory=$false, ParameterSetName="Copy-ComputerName")]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$true, ParameterSetName="Copy-Session")]
        [Parameter(Mandatory=$true, ParameterSetName="Copy-ComputerName")]
        [switch]$InstallViaCopy
    )

    $paramSplit = $PSCmdlet.ParameterSetName.Split("-")
    $ScriptCopyBehavior = $paramSplit[0]
    $SessionBehavior = $paramSplit[1]

    switch($SessionBehavior) {
        "Session" { 
            $ComputerName = $session.ComputerName
            $username = Invoke-Command -Session $Session -ScriptBlock {
                $(whoami).ToLowerInvariant()
            }
        }

        "ComputerName" {
            $sessionParameters = @{ "ComputerName" = $ComputerName }
            
            if ($PSBoundParameters.ContainsKey("Credential")) {
                $sessionParameters += @{ "Credential" = $Credential }
                $username = $Credential.UserName
            } else {
                $username = $(whoami).ToLowerInvariant()
            }

            $Session = New-PSSession @sessionParameters
        }

        default {
            throw [System.ArgumentException]::new(
                "Unrecognized session parameter set.", "SessionBehavior")
        }
    }
    
    $lookupTuple = [System.Tuple[string, string]]::new($ComputerName, $username)
    $existingSession = [System.Management.Automation.Runspaces.PSSession]$null
    if ($sessionDictionary.TryGetValue($lookupTuple, [ref]$existingSession)) {
        if ($existingSession.State -ne "Opened") {
            $sessionDictionary.Remove($existingSession)

            Remove-PSSession `
                    -Session $existingSession `
                    -WarningAction SilentlyContinue `
                    -ErrorAction SilentlyContinue
            
            $sessionDictionary.Add($lookupTuple, $Session)
        } else {
            $Session = $existingSession
        }
    } else {
        $sessionDictionary.Add($lookupTuple, $Session)
    }

    $moduleInfo = Get-CurrentModule
    $remoteModuleInfo = Get-Module `
            -PSSession $Session `
            -Name $moduleInfo.Name `
            -ListAvailable
    
    switch($ScriptCopyBehavior) {
        "Copy" {
            if ($null -eq $remoteModuleInfo) {
                Copy-RemoteModule -Session $Session
            } elseif ($moduleInfo.Version -ne $remoteModuleInfo.Version) {
                throw [PSSessionHybridManagementVersionMismatchException]::new(
                    $moduleInfo.Version, $remoteModuleInfo.Version)
            }
        }

        default {
            throw [System.ArgumentException]::new(
                "Unrecognized session parameter set.", "ScriptCopyBehavior")
        }
    }

    Invoke-Command `
            -Session $Session `
            -ArgumentList $moduleInfo.Name `
            -ScriptBlock {
                $moduleName = $args[0]
                Import-Module -Name $moduleName
            }

    return $Session
}

function Get-IsElevatedSession {
    [CmdletBinding()]
    param()

    switch((Get-OSPlatform)) {
        "Windows" {
            $currentPrincipal = [Security.Principal.WindowsPrincipal]::new(
                [Security.Principal.WindowsIdentity]::GetCurrent())
            $isAdmin = $currentPrincipal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)

            return $isAdmin
        }

        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}

function Test-IsElevatedSession {
    [CmdletBinding()]
    param()

    if (!(Get-IsElevatedSession)) {
        Write-Error `
            -Message "This cmdlet requires an elevated PowerShell session." `
            -ErrorAction Stop
    }
}

function Get-OSPlatform {
    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSEdition -eq "Desktop") {
        return "Windows"
    } else {
        $windows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)

        if ($windows) { 
            return "Windows"
        }
        
        $linux = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Linux)

        if ($linux) {
            return "Linux"
        }

        $osx = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::OSX)

        if ($osx) {
            return "OSX"
        }

        return "Unknown"
    }
}

function Get-OSVersion {
    [CmdletBinding()]
    param()

    switch((Get-OSPlatform)) {
        "Windows" {
            return [System.Environment]::OSVersion.Version
        }

        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}

function Get-WindowsInstallationType {
    [CmdletBinding()]
    param()

    if ((Get-OSPlatform) -ne "Windows") {
        throw [System.PlatformNotSupportedException]::new("Get-WindowsInstallationType is only supported in Windows environments.")
    }

    $installType = Get-ItemProperty `
            -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" `
            -Name InstallationType | `
        Select-Object -ExpandProperty InstallationType
    
    return $installType
}

function Get-OSFeature {
    [CmdletBinding()]
    param()

    switch((Get-OSPlatform)) {
        "Windows" {
            $winVer = Get-OSVersion

            switch((Get-WindowsInstallationType)) {
                "Client" {
                    Test-IsElevatedSession

                    $features = Get-WindowsCapability -Online | `
                        Select-Object `
                            @{ Name= "InternalName"; Expression = { $_.Name } },
                            @{ Name = "Name"; Expression = { $_.Name.Split("~")[0] } },
                            @{ Name = "Field1"; Expression = { $_.Name.Split("~")[1] } }, 
                            @{ Name = "Field2"; Expression = { $_.Name.Split("~")[2] } },
                            @{ Name = "Language"; Expression = { $_.Name.Split("~")[3] } },
                            @{ Name = "Version"; Expression = { $_.Name.Split("~")[4] } },
                            @{ Name = "Installed"; Expression = { $_.State -eq "Installed" } } | `
                        ForEach-Object {
                            if (![string]::IsNullOrEmpty($_.Language)) {
                                $Name = ($_.Name + "-" + $_.Language)
                            } else {
                                $Name = $_.Name
                            }

                            [OSFeature]::new(
                                $Name, 
                                $_.InternalName, 
                                $_.Version, 
                                $_.Installed, 
                                [OSFeatureKind]::WindowsClientCapability)
                        }

                    $features += Get-WindowsOptionalFeature -Online | 
                        Select-Object `
                            @{ Name = "InternalName"; Expression = { $_.FeatureName } }, 
                            @{ Name = "Name"; Expression = { $_.FeatureName } }, 
                            @{ Name = "Installed"; Expression = { $_.State -eq "Enabled" } } | `
                        ForEach-Object {
                            [OSFeature]::new(
                                $_.Name, 
                                $_.InternalName, 
                                $winVer, 
                                $_.Installed, 
                                [OSFeatureKind]::WindowsClientOptionalFeature)
                        }
                }

                { ($_ -eq "Server") -or ($_ -eq "Server Core") } {
                    $features = Get-WindowsFeature | `
                        Select-Object Name, Installed | `
                        ForEach-Object {
                            [OSFeature]::new(
                                $_.Name, 
                                $_.Name, 
                                $winVer, 
                                $_.Installed, 
                                [OSFeatureKind]::WindowsServerFeature)
                        }
                }
            }
        }

        "Linux" {
            throw [System.NotImplementedException]::new()
        }

        "OSX" {
            throw [System.NotImplementedException]::new()
        }

        default {
            throw [System.NotImplementedException]::new()
        }
    }

    return $features
}

function Install-OSFeature {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Name,

        [Parameter(Mandatory=$true, ParameterSetName="WindowsServer")]
        [switch]$WindowsServerFeature,

        [Parameter(Mandatory=$true, ParameterSetName="WindowsClientCapability")]
        [switch]$WindowsClientCapability,

        [Parameter(Mandatory=$true, ParameterSetName="WindowsClientOptionalFeature")]
        [switch]$WindowsClientOptionalFeature
    )

    switch ((Get-OSPlatform)) {
        "Windows" {
            switch((Get-WindowsInstallationType)) {
                "Client" {
                    Test-IsElevatedSession

                    if ($WindowsClientCapability) {
                        $foundMatches = $Name | `
                            ForEach-Object { Get-WindowsCapability -Online -Name "$_*" } | `
                            Select-Object Name, @{ Name = "FriendlyName"; Expression = { $_.Name.Split("~")[0] } }, State
                        
                        $notFoundMatches = $Name | `
                            Where-Object { $_ -notin ($foundMatches | Select-Object -ExpandProperty FriendlyName) }
                        
                        if ($null -ne $notFoundMatches) {
                            $sb = [System.Text.StringBuilder]::new()
                            $sb.Append("Could not find the following required modules: ") | Out-Null
                            for($i = 0; $i -lt $notFoundMatches.Length; $i++) {
                                if ($i -gt 0) {
                                    $sb.Append(", ") | Out-Null
                                }

                                $sb.Append($notFoundMatches[$i]) | Out-Null
                            }

                            $sb.Append(". You may need to install an external package, such as the RSAT package prior to Windows 10 version 1809. RSAT can be downloaded via https://www.microsoft.com/download/details.aspx?id=45520.") | Out-Null

                            Write-Error -Message $sb.ToString() -ErrorAction Stop
                        }

                        $foundMatches | `
                            Where-Object { $_.State -eq "NotPresent" } | `
                            Add-WindowsCapability -Online | `
                            Out-Null
                    }

                    if ($WindowsClientOptionalFeature) {
                        Enable-WindowsOptionalFeature -Online -FeatureName $Name | `
                            Out-Null
                    }
                }
        
                { ($_ -eq "Server") -or ($_ -eq "Server Core") } {
                    Install-WindowsFeature -Name $Name | `
                        Out-Null
                }
        
                default {
                    Write-Error -Message "Unknown Windows installation type $_" -ErrorAction Stop
                }
            }
        }

        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}

function Test-OSFeature {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$WindowsClientCapability,

        [Parameter(Mandatory=$false)]
        [string[]]$WindowsClientOptionalFeature,

        [Parameter(Mandatory=$false)]
        [string[]]$WindowsServerFeature
    )

    $features = Get-OSFeature

    switch((Get-OSPlatform)) {
        "Windows" {
            switch((Get-WindowsInstallationType)) {
                "Client" {
                    $foundCapabilities = $features | `
                        Where-Object { $_.FeatureKind -eq [OSFeatureKind]::WindowsClientCapability } | `
                        Where-Object { $_.Name -in $WindowsClientCapability } 

                    $notFoundCapabilities = $WindowsClientCapability | `
                        Where-Object { $_ -notin ($foundCapabilities | Select-Object -ExpandProperty Name) }
                    
                    if ($null -eq $notFoundOptionalFeatures) {
                        Install-OSFeature -Name $notFoundCapabilities -WindowsClientCapability
                    }

                    $foundOptionalFeatures = $features | `
                        Where-Object { $_.FeatureKind -eq [OSFeatureKind]::WindowsClientOptionalFeature } | `
                        Where-Object { $_.Name -in $WindowsClientOptionalFeature }

                    $notFoundOptionalFeatures = $WindowsClientOptionalFeature | `
                        Where-Object { $_ -notin ($foundOptionalFeatures | Select-Object -ExpandProperty Name ) }

                    if ($null -eq $notFoundOptionalFeatures) {
                        Install-OSFeature -Name $notFoundOptionalFeatures -WindowsClientOptionalFeature
                    }
                }

                { ($_ -eq "Server") -or ($_ -eq "Server Core") } {
                    $foundFeatures = $features | `
                        Where-Object { $_.FeatureKind -eq [OSFeatureKind]::WindowsServerFeature } | `
                        Where-Object { $_.Name -in $WindowsServerFeature }
                    
                    $notFoundFeatures = $features | `
                        Where-Object { $_ -notin ($foundFeatures | Select-Object -ExpandProperty Name) }
                    
                    if ($null -eq $notFoundFeatures) {
                        Install-OSFeature -Name $notFoundFeatures -WindowsServerFeature
                    }
                }
            }
        }

        "Linux" {
            throw [System.NotImplementedException]::new()
        }

        "OSX" {
            throw [System.NotImplementedException]::new()
        }

        default {
            throw [System.NotImplementedException]::new()
        }
    }
}

function Get-ADDomainInternal {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [string]$Server
    )

    process {
        switch((Get-OSPlatform)) {
            "Windows" {
                $parameters = @{}

                if (![string]::IsNullOrEmpty($Identity)) {
                    $parameters += @{ "Identity" = $Identity }
                }

                if ($null -ne $Credential) {
                    $parameters += @{ "Credential" = $Credential }
                }

                if (![string]::IsNullOrEmpty($Server)) {
                    $parameters += @{ "Server" = $Server }
                }

                return Get-ADDomain @parameters
            }

            "Linux" {
                throw [System.PlatformNotSupportedException]::new()
            }

            "OSX" {
                throw [System.PlatformNotSupportedException]::new()
            }

            default {
                throw [System.PlatformNotSupportedException]::new()
            }
        }
    }
}

function Get-ADComputerInternal {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ParameterSetName="FilterParameterSet")]
        [string]$Filter,

        [Parameter(Mandatory=$true, ParameterSetName="IdentityParameterSet")]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,
        
        [Parameter(Mandatory=$false)]
        [string]$Server
    )

    switch ((Get-OSPlatform)) {
        "Windows" {
            $parameters = @{}

            if (![string]::IsNullOrEmpty($Filter)) {
                $parameters += @{ "Filter" = $Filter }
            }

            if (![string]::IsNullOrEmpty($Identity)) {
                $parameters += @{ "Identity" = $Identity }
            }

            if ($null -ne $Properties) {
                $parameters += @{ "Properties" = $Properties }
            }

            if (![string]::IsNullOrEmpty($Server)) {
                $parameters += @{ "Server" = $Server }
            }

            return Get-ADComputer @parameters
        }

        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}

function ConvertTo-EncodedJson {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object]$Object,

        [Parameter(Mandatory=$false)]
        [int]$Depth = 2
    )

    $Object = ($Object | ConvertTo-Json -Compress -Depth $Depth).
        Replace("`"", "*").
        Replace("[", "<").
        Replace("]", ">").
        Replace("{", "^").
        Replace("}", "%")
    
    return $Object
}

function ConvertFrom-EncodedJson {
    [CmdletBinding()]
    
    param(
        [string]$String
    )

    $String = $String.
        Replace("*", "`"").
        Replace("<", "[").
        Replace(">", "]").
        Replace("^", "{").
        Replace("%", "}")
    
    return (ConvertFrom-Json -InputObject $String)
}

function Write-OdjBlob {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$OdjBlob,

        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $byteArray = [System.Byte[]]@()
    $byteArray += 255
    $byteArray += 254

    $byteArray += [System.Text.Encoding]::Unicode.GetBytes($OdjBlob)

    $byteArray += 0
    $byteArray += 0

    $writer = [System.IO.File]::Create($Path)
    $writer.Write($byteArray, 0, $byteArray.Length)

    $writer.Close()
    $writer.Dispose()
}

function Register-OfflineMachine {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$MachineName,
        
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$MachineOU,

        [Parameter(Mandatory=$false)]
        [string]$DCName,
        
        [Parameter(Mandatory=$false)]
        [switch]$Reuse,

        [Parameter(Mandatory=$false)]
        [switch]$NoSearch,
        
        [Parameter(Mandatory=$false)]
        [switch]$DefaultPassword,

        [Parameter(Mandatory=$false)]
        [switch]$RootCACertificates,

        [Parameter(Mandatory=$false)]
        [string]$CertificateTemplate,

        [Parameter(Mandatory=$false)]
        [string[]]$PolicyNames,

        [Parameter(Mandatory=$false)]
        [string[]]$PolicyPaths,
        
        [Parameter(Mandatory=$false)]
        [string]$Netbios,
        
        [Parameter(Mandatory=$false)]
        [string]$PersistentSite,

        [Parameter(Mandatory=$false)]
        [string]$DynamicSite,

        [Parameter(Mandatory=$false)]
        [string]$PrimaryDNS
    )

    process {
        $properties = @{}

        if ([string]::IsNullOrEmpty($Domain)) {
            $Domain = Get-ADDomainInternal | `
                Select-Object -ExpandProperty DNSRoot
        } else {
            try {
                Get-ADDomainInternal -Identity $Domain | Out-Null
            } catch {
                throw [System.ArgumentException]::new(
                    "Provided domain $Domain was not found.", "Domain")
            }
        }

        $properties += @{ "Domain" = $Domain }

        if (![string]::IsNullOrEmpty($MachineName)) {
            $computer = Get-ADComputerInternal `
                    -Filter "Name -eq `"$MachineName`"" `
                    -Server $Domain

            if ($null -ne $computer) {
                throw [System.ArgumentException]::new(
                    "Machine $MachineName already exists.", "MachineName")
            }
        } else {
            throw [System.ArgumentException]::new(
                "The machine name property must not be empty.", "MachineName")
        }

        $properties += @{ "MachineName" = $MachineName }

        if ($PSBoundParameters.ContainsKey("MachineOU")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("DCName")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("Reuse")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("NoSearch")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("DefaultPassword")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("RootCACertificates")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("CertificateTemplate")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PolicyNames")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PolicyPaths")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("Netbios")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("PersistentSite")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("DynamicSite")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PrimaryDNS")) {
            throw [System.NotImplementedException]::new()
        }

        switch((Get-OSPlatform)) {
            "Windows" {
                return Register-OfflineMachineWindows @properties
            }

            "Linux" {
                throw [System.PlatformNotSupportedException]::new()
            }

            "OSX" {
                throw [System.PlatformNotSupportedException]::new()
            }

            default {
                throw [System.PlatformNotSupportedException]::new()
            }
        }
    }
}

function Register-OfflineMachineWindows {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$MachineName,
        
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$MachineOU,

        [Parameter(Mandatory=$false)]
        [string]$DCName,
        
        [Parameter(Mandatory=$false)]
        [switch]$Reuse,

        [Parameter(Mandatory=$false)]
        [switch]$NoSearch,
        
        [Parameter(Mandatory=$false)]
        [switch]$DefaultPassword,

        [Parameter(Mandatory=$false)]
        [switch]$RootCACertificates,

        [Parameter(Mandatory=$false)]
        [string]$CertificateTemplate,

        [Parameter(Mandatory=$false)]
        [string[]]$PolicyNames,

        [Parameter(Mandatory=$false)]
        [string[]]$PolicyPaths,
        
        [Parameter(Mandatory=$false)]
        [string]$Netbios,
        
        [Parameter(Mandatory=$false)]
        [string]$PersistentSite,

        [Parameter(Mandatory=$false)]
        [string]$DynamicSite,

        [Parameter(Mandatory=$false)]
        [string]$PrimaryDNS
    )

    process {
        if ($PSBoundParameters.ContainsKey("MachineOU")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("DCName")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("Reuse")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("NoSearch")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("DefaultPassword")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("RootCACertificates")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("CertificateTemplate")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PolicyNames")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PolicyPaths")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("Netbios")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("PersistentSite")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("DynamicSite")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PrimaryDNS")) {
            throw [System.NotImplementedException]::new()
        }

        $sb = [System.Text.StringBuilder]::new()
        $sb.Append("djoin.exe /provision") | Out-Null

        $sb.Append(" /domain $Domain") | Out-Null
        $sb.Append(" /machine $MachineName") | Out-Null

        $tempFile = [System.IO.Path]::GetTempFileName()
        $sb.Append(" /savefile $tempFile") | Out-Null
        
        $djoinResult = Invoke-Expression -Command $sb.ToString()

        if ($djoinResult -like "*Computer provisioning completed successfully*") {
            $blobArray = [System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $tempFile))
            $blobArray = $blobArray[0..($blobArray.Length-3)]

            Remove-Item -Path $tempFile

            return [System.Text.Encoding]::Unicode.GetString($blobArray)
        } else {
            Write-Error `
                    -Message "Machine $MachineName provisioning failed. DJoin output: $djoinResult" `
                    -ErrorAction Stop
        }
    }
}

function Join-OfflineMachine {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$OdjBlob,

        [Parameter(Mandatory=$false, ParameterSetName="WindowsParameterSet")]
        [string]$WindowsPath
    )

    switch((Get-OSPlatform)) {
        "Windows" {
            if ([string]::IsNullOrEmpty($WindowsPath)) {
                $WindowsPath = $env:windir
            }

            $tempFile = [System.IO.Path]::GetTempFileName()
            Write-OdjBlob -OdjBlob $OdjBlob -Path $tempFile

            $sb = [System.Text.StringBuilder]::new()
            $sb.Append("djoin.exe /requestodj") | Out-Null
            $sb.Append(" /loadfile $tempFile") | Out-Null
            $sb.Append(" /windowspath $WindowsPath") | Out-Null
            $sb.Append(" /localos") | Out-Null

            $djoinResult = Invoke-Expression -Command $sb.ToString()
            if ($djoinResult -like "*successfully*") {
                Write-Information -MessageData "Machine successfully provisioned. A reboot is required for changes to be applied."
                Remove-Item -Path $tempFile
            } else {
                Write-Error `
                        -Message "Machine failed to provision. DJoin output: $djoinResult" `
                        -ErrorAction Stop
            }
        }
        
        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}

function New-RegistryItem {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$ParentPath,

        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $ParentPath = $args[0]
    $Name = $args[1]

    if ((Get-OSPlatform) -eq "Windows") {
        $regItem = Get-ChildItem -Path $ParentPath | `
            Where-Object { $_.PSChildName -eq $Name }
        
        if ($null -eq $regItem) {
            New-Item -Path ($ParentPath + "\" + $Name) | `
                Out-Null
        }
    }
}

function New-RegistryItemProperty {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    if ((Get-OSPlatform) -eq "Windows") {
        $regItemProperty = Get-ItemProperty -Path $Path | `
            Where-Object { $_.Name -eq $Name }
        
        if ($null -eq $regItemProperty) {
            New-ItemProperty `
                    -Path $Path `
                    -Name $Name `
                    -Value $Value | `
                Out-Null
        } else {
            Set-ItemProperty `
                    -Path $Path `
                    -Name $Name `
                    -Value $Value | `
                Out-Null
        }
    }  
}

function Get-ADUserObjectPermissions {

}

function Resolve-DnsNameInternal {
    [CmdletBinding()]
    
    param(
        [Parameter(
            Mandatory=$true, 
            Position=0, 
            ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)]
        [string]$Name
    )

    process {
        switch((Get-OSPlatform)) {
            "Windows" {
                return (Resolve-DnsName -Name $Name)
            }

            "Linux" {
                throw [System.PlatformNotSupportedException]::new()
            }

            "OSX" {
                throw [System.PlatformNotSupportedException]::new()
            }

            default {
                throw [System.PlatformNotSupportedException]::new()
            }
        }
    }
}

function Add-AzDnsForwardingRule {
    [CmdletBinding()]
    
    param(
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyCollection()]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$true, ParameterSetName="AzureEndpointParameterSet")]
        [ValidateSet(
            "StorageEndpoint", 
            "SqlDatabaseEndpoint", 
            "KeyVaultEndpoint")]
        [string]$AzureEndpoint,
        
        [Parameter(Mandatory=$true, ParameterSetName="ManualParameterSet")]
        [string]$DomainName,
        
        [Parameter(Mandatory=$false, ParameterSetName="ManualParameterSet")]
        [switch]$AzureResource,

        [Parameter(Mandatory=$true, ParameterSetName="ManualParameterSet")]
        [System.Collections.Generic.HashSet[string]]$MasterServers,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Overwrite",
            "Merge",
            "Disallow"
        )]
        [string]$ConflictBehavior = "Overwrite"
    )
    
    process {
        Write-Verbose -Message $DnsForwardingRuleSet.GetHashCode().ToString()

        $forwardingRules = $DnsForwardingRuleSet.DnsForwardingRules

        if ($PSCmdlet.ParameterSetName -eq "AzureEndpointParameterSet") {
            $subscriptionContext = Get-AzContext
            if ($null -eq $subscriptionContext) {
                throw [AzureLoginRequiredException]::new()
            }
            $environmentEndpoints = Get-AzEnvironment -Name $subscriptionContext.Environment

            switch($AzureEndpoint) {
                "StorageEndpoint" {
                    $DomainName = $environmentEndpoints.StorageEndpointSuffix
                    $AzureResource = $true

                    $MasterServers = [System.Collections.Generic.HashSet[string]]::new()
                    $MasterServers.Add($azurePrivateDnsIp) | Out-Null
                }

                "SqlDatabaseEndpoint" {
                    $reconstructedEndpoint = [string]::Join(".", (
                        $environmentEndpoints.SqlDatabaseDnsSuffix.Split(".") | Where-Object { ![string]::IsNullOrEmpty($_) }))
                    
                    $DomainName = $reconstructedEndpoint
                    $AzureResource = $true

                    $MasterServers = [System.Collections.Generic.HashSet[string]]::new()
                    $MasterServers.Add($azurePrivateDnsIp) | Out-Null
                }

                "KeyVaultEndpoint" {
                    $DomainName = $environmentEndpoints.AzureKeyVaultDnsSuffix
                    $AzureResource = $true

                    $MasterServers = [System.Collections.Generic.HashSet[string]]::new()
                    $MasterServers.Add($azurePrivateDnsIp) | Out-Null
                }
            }
        }

        $forwardingRule = [DnsForwardingRule]::new($DomainName, $AzureResource, $MasterServers)
        $conflictRule = [DnsForwardingRule]$null

        if ($forwardingRules.TryGetValue($forwardingRule, [ref]$conflictRule)) {
            switch($ConflictBehavior) {
                "Overwrite" {
                    $forwardingRules.Remove($conflictRule) | Out-Null
                    $forwardingRules.Add($forwardingRule) | Out-Null
                }

                "Merge" {
                    if ($forwardingRule.AzureResource -ne $conflictRule.AzureResource) {
                        throw [System.ArgumentException]::new(
                            "Azure resource status does not match for domain name $domain.", "AzureResource")
                    }

                    foreach($newMasterServer in $forwardingRule.MasterServers) {
                        $conflictRule.MasterServers.Add($newMasterServer) | Out-Null
                    }
                }

                "Disallow" {
                    throw [System.ArgumentException]::new(
                        "Domain name $domainName already exists in ruleset.", "DnsForwardingRules") 
                }
            }
        } else {
            $forwardingRules.Add($forwardingRule) | Out-Null
        }

        return $DnsForwardingRuleSet
    }
}

function New-AzDnsForwardingRuleSet {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "StorageEndpoint", 
            "SqlDatabaseEndpoint", 
            "KeyVaultEndpoint")]
        [System.Collections.Generic.HashSet[string]]$AzureEndpoints,

        [Parameter(Mandatory=$false)]
        [switch]$SkipOnPremisesDns,

        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.HashSet[string]]$OnPremDnsHostNames,

        [Parameter(Mandatory=$false)]
        [string]$OnPremDomainName,

        [Parameter(Mandatory=$false)]
        [switch]$SkipParentDomain
    )

    $ruleSet = [DnsForwardingRuleSet]::new()
    foreach($azureEndpoint in $AzureEndpoints) {
        Add-AzDnsForwardingRule -DnsForwardingRuleSet $ruleSet -AzureEndpoint $azureEndpoint | Out-Null
    }

    if (!$SkipOnPremisesDns) {
        if ([string]::IsNullOrEmpty($OnPremDomainName)) {
            $domain = Get-ADDomainInternal
        } else {
            $domain = Get-ADDomainInternal -Identity $OnPremDomainName
        }

        if (!$SkipParentDomain) {
            while($null -ne $domain.ParentDomain) {
                $domain = Get-ADDomainInternal -Identity $domain.ParentDomain
            }
        }

        if ($null -eq $OnPremDnsHostNames) {
            $onPremDnsServers = Resolve-DnsNameInternal -Name $domain.DNSRoot | `
                Where-Object { $_.Type -eq "A" } | `
                Select-Object -ExpandProperty IPAddress
        } else {
            $onPremDnsServers = $OnPremDnsHostNames | `
                Resolve-DnsNameInternal | `
                Where-Object { $_.Type -eq "A" } | `
                Select-Object -ExpandProperty IPAddress
        }

        Add-AzDnsForwardingRule `
                -DnsForwardingRuleSet $ruleSet `
                -DomainName $domain.DNSRoot `
                -MasterServers $OnPremDnsServers | `
            Out-Null
    }

    return $ruleSet
}

function Clear-DnsClientCacheInternal {
    switch((Get-OSPlatform)) {
        "Windows" {
            Clear-DnsClientCache
        }

        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}

function Push-AzDnsServerConfiguration {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$true)]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Overwrite", 
            "Merge", 
            "Disallow")]
        [string]$ConflictBehavior = "Overwrite"
    )

    $DnsForwardingRuleSet = $args[0]
    $ConflictBehavior = $args[1]

    Test-OSFeature -WindowsServerFeature "DNS", "RSAT-DNS-Server"

    $rules = $DnsForwardingRuleSet.DnsForwardingRules
    foreach($rule in $rules) {
        $existingZone = Get-DnsServerZone | `
            Where-Object { $_.ZoneName -eq $rule.DomainName }

        $masterServers = $rule.MasterServers
        if ($null -ne $existingZone) {
            switch($ConflictBehavior) {
                "Overwrite" {
                    $existingZone | Remove-DnsServerZone `
                            -Confirm:$false `
                            -Force
                }

                "Merge" {
                    $existingMasterServers = $existingZone | `
                        Select-Object -ExpandProperty MasterServers | `
                        Select-Object -ExpandProperty IPAddressToString
                    
                    $masterServers = [System.Collections.Generic.HashSet[string]]::new(
                        $masterServers)
                    
                    foreach($existingServer in $existingMasterServers) {
                        $masterServers.Add($existingServer) | Out-Null
                    }

                    $existingZone | Remove-DnsServerZone `
                            -Confirm:$false `
                            -Force
                }

                "Disallow" {
                    throw [System.ArgumentException]::new(
                        "The DNS forwarding zone already exists", "DnsForwardingRuleSet")
                }

                default {
                    throw [System.ArgumentException]::new(
                        "Unexpected conflict behavior $ConflictBehavior", "ConflictBehavior")
                }
            }
        }

        Add-DnsServerConditionalForwarderZone `
                -Name $rule.DomainName `
                -MasterServers $masterServers
    }
}

function Push-OnPremDnsServerConfiguration {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$true)]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.HashSet[string]]$AzDnsForwarderIpAddress,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Overwrite", 
            "Merge", 
            "Disallow")]
        [string]$ConflictBehavior = "Overwrite"
    )

    $DnsForwardingRuleSet = $args[0]
    $AzDnsForwarderIpAddress = $args[1]
    $ConflictBehavior = $args[2]

    $onPremRules = $DnsForwardingRuleSet | `
        Select-Object -ExpandProperty DnsForwardingRules | `
        Where-Object { !$_.AzureResource }

    foreach($rule in $onPremRules) {
        $zone = Get-DnsServerZone | `
            Where-Object { $_.ZoneName -eq $rule.DomainName }

        $masterServers = $AzDnsForwarderIpAddress
        if ($null -ne $zone) {
            switch($ConflictBehavior) {
                "Overwrite" {
                    $zone | Remove-DnsServerZone `
                            -Confirm:$false `
                            -Force
                }

                "Merge" {
                    $existingMasterServers = $zone | `
                        Select-Object -ExpandProperty MasterServers | `
                        Select-Object -ExpandProperty IPAddressToString
                    
                    $masterServers = [System.Collections.Generic.HashSet[string]]::new(
                        $AzDnsForwarderIpAddress)

                    foreach($existingServer in $existingMasterServers) {
                        $masterServers.Add($existingServer) | Out-Null
                    }
                    
                    $zone | Remove-DnsServerZone `
                            -Confirm:$false `
                            -Force
                }

                "Disallow" {
                    throw [System.ArgumentException]::new(
                        "The DNS forwarding zone already exists", "DnsForwardingRuleSet")
                }

                default {
                    throw [System.ArgumentException]::new(
                        "Unexpected conflict behavior $ConflictBehavior", "ConflictBehavior")
                }
            }
        }
        
        Add-DnsServerConditionalForwarderZone `
                -Name $rule.DomainName `
                -MasterServers $masterServers
        
        Clear-DnsClientCache
        Clear-DnsServerCache `
                -Confirm:$false `
                -Force
    }
}

function New-AzDnsForwarder {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$true)]
        [string]$DnsServerResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$VirtualNetworkResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$VirtualNetworkName,

        [Parameter(Mandatory=$true)]
        [string]$VirtualNetworkSubnetName,
        
        [Parameter(Mandatory=$false)]
        [string]$DnsForwarderRootName = "DnsFwder",

        [Parameter(Mandatory=$false)]
        [string]$DomainToJoin,

        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$VmTemporaryPassword,

        [Parameter(Mandatory=$true)]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$false)]
        [int]$DnsForwarderRedundancyCount = 2,

        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.HashSet[string]]$OnPremDnsHostNames,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$SkipParentDomain
    )

    # Verify virtual network is there. $virtualNetwork will be used to populate
    # information later on.
    $virtualNetwork = Get-AzVirtualNetwork `
            -ResourceGroupName $virtualNetworkResourceGroupName | `
        Where-Object { $_.Name -eq $virtualNetworkName }

    if ($null -eq $virtualNetwork) {
        Write-Error `
                -Message "Virtual network $virtualNetworkName does not exist in resource group $virtualNetworkResourceGroupName." `
                -ErrorAction Stop
    }

    # Verify virtual network's subnet. 
    $virtualNetworkSubnet = $virtualNetwork | `
        Select-Object -ExpandProperty Subnets | `
        Where-Object { $_.Name -eq $virtualNetworkSubnetName } 

    if ($null -eq $virtualNetworkSubnet) {
        Write-Error `
                -Message "Subnet $virtualNetworkSubnetName does not exist in virtual network $virtualNetworkName." `
                -ErrorAction Stop
    }

    # Create resource group for the DNS forwarders, if it hasn't already
    # been created. The resource group will have the same location as the vnet.
    $dnsServerResourceGroup = Get-AzResourceGroup | `
        Where-Object { $_.ResourceGroupName -eq $dnsServerResourceGroupName }

    if ($null -eq $dnsServerResourceGroup) { 
        $dnsServerResourceGroup = New-AzResourceGroup `
                -Name $dnsServerResourceGroupName `
                -Location $virtualNetwork.Location
    }

    # Get domain to join
    if ([string]::IsNullOrEmpty($DomainToJoin)) {
        $DomainToJoin = (Get-ADDomainInternal).DNSRoot
    } else {
        try {
            $DomainToJoin = (Get-ADDomainInternal -Identity $DomainToJoin).DNSRoot
        } catch {
            throw [System.ArgumentException]::new(
                "Could not find the domain $DomainToJoin", "DomainToJoin")
        }
    }

    # Get incrementor 
    $intCaster = {
        param($name, $rootName, $domainName)

        $str = $name.
            Replace(".$domainName", "").
            ToLowerInvariant().
            Replace("$($rootName.ToLowerInvariant())-", "")
        
        $i = -1
        if ([int]::TryParse($str, [ref]$i)) {
            return $i
        } else {
            return -1
        }
    }

    $filterCriteria = ($DnsForwarderRootName + "-*")
    $currentIncrementor = Get-ADComputerInternal -Filter { Name -like $filterCriteria } | 
        Select-Object Name, 
            @{ 
                Name = "Incrementor"; 
                Expression = { $intCaster.Invoke($_.DNSHostName, $DnsForwarderRootName, $DomainToJoin) } 
            } | `
        Select-Object -ExpandProperty Incrementor | `
        Measure-Object -Maximum | `
        Select-Object -ExpandProperty Maximum
    
    if ($null -eq $currentIncrementor) {
        $currentIncrementor = -1
    }

    if ($currentIncrementor -lt 1000) {
        $currentIncrementor++
    }

    # Register new DNS servers for offline domain join
    if ($DnsForwarderRedundancyCount -ne 2) {
        throw [System.NotImplementedException]::new("Only exactly 2 forwarders are supported.")
    }

    $redundancyTop = $currentIncrementor + $DnsForwarderRedundancyCount
    $dnsForwarderNames = [string[]]@()
    while ($currentIncrementor -lt $redundancyTop) {
        $dnsForwarderNames += ($DnsForwarderRootName + "-" + $currentIncrementor)
        $currentIncrementor++
    }
    
    $odjBlobs = $dnsForwarderNames | `
        Register-OfflineMachine -Domain $DomainToJoin | `
        ConvertTo-SecureString -AsPlainText -Force
    
    ## Encode ruleset
    $encodedDnsForwardingRuleSet = $DnsForwardingRuleSet | ConvertTo-EncodedJson -Depth 3

    try {
        $templateResult = New-AzResourceGroupDeployment `
            -ResourceGroupName $DnsServerResourceGroupName `
            -TemplateUri $DnsForwarderTemplate `
            -location $virtualNetwork.Location `
            -virtualNetworkResourceGroupName $VirtualNetworkResourceGroupName `
            -virtualNetworkName $VirtualNetworkName `
            -virtualNetworkSubnetName $VirtualNetworkSubnetName `
            -dnsForwarderRootName $DnsForwarderRootName `
            -dnsForwarderTempPassword $VmTemporaryPassword `
            -odjBlob0 $odjBlobs[0] `
            -odjBlob1 $odjBlobs[1] `
            -encodedForwardingRules $encodedDnsForwardingRuleSet
    } catch {
        Write-Verbose $_
        Write-Error -Message "This error message will eventually be replaced by a rollback functionality." -ErrorAction Stop
    }

    $dnsForwarder0PrivateIp = $templateResult.Outputs.'dnsForwarder0-PrivateIP'.Value
    $dnsForwarder1PrivateIp = $templateResult.Outputs.'dnsForwarder1-PrivateIP'.Value

    if ($null -eq $virtualNetwork.DhcpOptions.DnsServers) {
        $virtualNetwork.DhcpOptions.DnsServers = 
            [System.Collections.Generic.List[string]]::new()
    }
    
    $virtualNetwork.DhcpOptions.DnsServers.Add($dnsForwarder0PrivateIp)
    $virtualNetwork.DhcpOptions.DnsServers.Add($dnsForwarder1PrivateIp)
    $virtualNetwork | Set-AzVirtualNetwork | Out-Null

    foreach($dnsForwarder in $dnsForwarderNames) {
        Restart-AzVM `
                -ResourceGroupName $DnsServerResourceGroupName `
                -Name $dnsForwarder | `
            Out-Null
    }

    # This should be moved up
    if ($null -eq $OnPremDnsHostNames) {
        $onPremDnsServers = $DnsForwardingRuleSet.DnsForwardingRules | `
            Where-Object { $_.AzureResource -eq $false } | `
            Select-Object -ExpandProperty MasterServers
        
        $OnPremDnsHostNames = $onPremDnsServers | `
            ForEach-Object { [System.Net.Dns]::GetHostEntry($_) } | `
            Select-Object -ExpandProperty HostName
    }

    foreach($server in $OnPremDnsHostNames) {
        # This assumes that a credential is given.
        $session = Initialize-RemoteSession `
                -ComputerName $server `
                -Credential $Credential `
                -InstallViaCopy
        
        $serializedRuleSet = $DnsForwardingRuleSet | ConvertTo-Json -Compress -Depth 3
        Invoke-Command `
                -Session $session `
                -ArgumentList $serializedRuleSet, $dnsForwarder0PrivateIp, $dnsForwarder1PrivateIp `
                -ScriptBlock {
                    $DnsForwardingRuleSet = [DnsForwardingRuleSet]::new(($args[0] | ConvertFrom-Json))
                    $dnsForwarder0PrivateIp = $args[1]
                    $dnsForwarder1PrivateIp = $args[2]

                    Push-OnPremDnsServerConfiguration `
                            -DnsForwardingRuleSet $DnsForwardingRuleSet `
                            -AzDnsForwarderIpAddress $dnsForwarder0PrivateIp, $dnsForwarder1PrivateIp 
                }
    }    
    
    Clear-DnsClientCacheInternal
}

function Mount-AzFileShare {

}

function Dismount-AzFileShare {

}