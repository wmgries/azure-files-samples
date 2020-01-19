# Module constants
Add-Type -TypeDefinition @"
    public class PSSessionElevationRequiredException : System.Exception { }

    public class DnsForwardingRule {
        public string DomainName { get; protected set; }
        public bool AzureResource { get; protected set; }
        public System.Collections.Generic.ISet<string> MasterServers { get; protected set; }  

        public DnsForwardingRule(string domainName, bool azureResource, System.Collections.Generic.ISet<string> masterServers) {
            DomainName = domainName;
            AzureResource = azureResource;
            MasterServers = masterServers; 
        }

        public DnsForwardingRule(string domainName, bool azureResource, System.Collections.Generic.IEnumerable<string> masterServers) {
            DomainName = domainName;
            AzureResource = azureResource;
            MasterServers = new System.Collections.Generic.HashSet<string>(masterServers);
        }
        
        public override int GetHashCode() {
            return DomainName.GetHashCode();
        }

        public override bool Equals(object obj) {
            return obj.GetHashCode() == GetHashCode();
        }
    }

    public class DnsForwardingRuleSet {
        public System.Collections.Generic.ISet<DnsForwardingRule> DnsForwardingRules { get; protected set; }

        public DnsForwardingRuleSet() {
            DnsForwardingRules = new System.Collections.Generic.HashSet<DnsForwardingRule>();
        }
    }
"@

$azurePrivateDnsIp = "168.63.129.16"
$DnsForwarderTemplate = "https://raw.githubusercontent.com/wmgries/azure-files-samples/dfsn/dns-forwarder/azuredeploy.json"

function Get-IsElevatedSession {
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
    if ((Get-IsElevatedSession)) {
        Write-Error `
            -Message "This cmdlet requires an elevated PowerShell session." `
            -ErrorAction Stop
    }
}

function Get-OSPlatform {
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
    if ((Get-OSPlatform) -ne "Windows") {
        throw [System.PlatformNotSupportedException]::new("Get-WindowsInstallationType is only supported in Windows environments.")
    }

    $installType = Get-ItemProperty `
            -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" `
            -Name InstallationType | `
        Select-Object -ExpandProperty InstallationType
    
    return $installType
}

function Install-CmdletRequiredModules {
    param(
        [string[]]$WindowsClientCapabilities,
        [string[]]$WindowsServerFeatures
    )

    switch ((Get-OSPlatform)) {
        "Windows" {
            Test-IsElevatedSession

            switch((Get-WindowsInstallationType)) {
                "Client" {
                    $foundMatches = $WindowsClientCapabilities | `
                        ForEach-Object { Get-WindowsCapability -Online -Name "$_*" } | `
                        Select-Object Name, @{ Name = "FriendlyName"; Expression = { $_.Name.Split("~")[0] } }, State
                    
                    $notFoundMatches = $WindowsClientCapabilities | `
                        Where-Object { $_ -notin ($foundMatches | Select-Object -ExpandProperty FriendlyName) }
                    
                    if ($null -ne $notFoundMatches) {
                        $sb = [System.Text.StringBuilder]::new()
                        $sb.Append("Could not find the following required modules: ")
                        for($i = 0; $i -lt $notFoundMatches.Length; $i++) {
                            if ($i -gt 0) {
                                $sb.Append(", ")
                            }

                            $sb.Append($notFoundMatches[$i])
                        }

                        $sb.Append(". You may need to install an external package, such as the RSAT package prior to Windows 10 version 1809. RSAT can be downloaded via https://www.microsoft.com/download/details.aspx?id=45520.")

                        Write-Error -Message $sb.ToString() -ErrorAction Stop
                    }

                    $foundMatches | `
                        Where-Object { $_.State -eq "NotPresent" } | `
                        Add-WindowsCapability -Online | `
                        Out-Null
                }
        
                { ($_ -eq "Server") -or ($_ -eq "Server Core") } {
                    Install-WindowsFeature -Name $WindowsServerFeatures | `
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

function Get-ADDomainInternal {
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

            if ($null -ne $Server) {
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
    param(
        [string]$String,
        [int]$Depth = 2
    )

    $String = ($String | ConvertTo-Json -Compress -Depth $Depth).
        Replace("`"", "*").
        Replace("[", "<").
        Replace("]", ">").
        Replace("{", "^").
        Replace("}", "%")
    
    return $String
}

function ConvertFrom-EncodedJson {
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
                Get-ADDomainInternal -Identity $Domain 
            } catch {
                throw [System.ArgumentException]::new(
                    "Provided domain $Domain was not found.", "Domain")
            }
        }

        $properties += @{ "Domain" = $Domain }

        if (![string]::IsNullOrEmpty($MachineName)) {
            $computer = Get-ADComputerInternal -Filter { "Name" -eq $MachineName }
            if ($null -ne $computer) {
                throw [System.ArgumentException]::new(
                    "Machine $MachineName already exists.", "MachineName")
            }
        } else {
            throw [System.ArgumentException]::new(
                "The machine name property must not be empty.", "MachineName")
        }

        $properties += @{ "MachineName" = $MachineName }

        if (![string]::IsNullOrEmpty($MachineOU)) {
            throw [System.NotImplementedException]::new()
        }
    
        if (![string]::IsNullOrEmpty($DCName)) {
            throw [System.NotImplementedException]::new()
        }
    
        if (!$Reuse) {
            throw [System.NotImplementedException]::new()
        }
        
        if (!$NoSearch) {
            throw [System.NotImplementedException]::new()
        }
        
        if (!$DefaultPassword) {
            throw [System.NotImplementedException]::new()
        }
    
        if (!$RootCACertificates) {
            throw [System.NotImplementedException]::new()
        }
    
        if (![string]::IsNullOrEmpty($CertificateTemplate)) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($null -eq $PolicyNames) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($null -eq $PolicyPaths) {
            throw [System.NotImplementedException]::new()
        }
        
        if (![string]::IsNullOrEmpty($Netbios)) {
            throw [System.NotImplementedException]::new()
        }
        
        if (![string]::IsNullOrEmpty($PersistentSite)) {
            throw [System.NotImplementedException]::new()
        }
    
        if (![string]::IsNullOrEmpty($DynamicSite)) {
            throw [System.NotImplementedException]::new()
        }
    
        if (![string]::IsNullOrEmpty($PrimaryDNS)) {
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
        if (![string]::IsNullOrEmpty($MachineOU)) {
            throw [System.NotImplementedException]::new()
        }
    
        if (![string]::IsNullOrEmpty($DCName)) {
            throw [System.NotImplementedException]::new()
        }
    
        if (!$Reuse) {
            throw [System.NotImplementedException]::new()
        }
        
        if (!$NoSearch) {
            throw [System.NotImplementedException]::new()
        }
        
        if (!$DefaultPassword) {
            throw [System.NotImplementedException]::new()
        }
    
        if (!$RootCACertificates) {
            throw [System.NotImplementedException]::new()
        }
    
        if (![string]::IsNullOrEmpty($CertificateTemplate)) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($null -eq $PolicyNames) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($null -eq $PolicyPaths) {
            throw [System.NotImplementedException]::new()
        }
        
        if (![string]::IsNullOrEmpty($Netbios)) {
            throw [System.NotImplementedException]::new()
        }
        
        if (![string]::IsNullOrEmpty($PersistentSite)) {
            throw [System.NotImplementedException]::new()
        }
    
        if (![string]::IsNullOrEmpty($DynamicSite)) {
            throw [System.NotImplementedException]::new()
        }
    
        if (![string]::IsNullOrEmpty($PrimaryDNS)) {
            throw [System.NotImplementedException]::new()
        }

        $sb = [System.Text.StringBuilder]::new()
        $sb.Append("djoin.exe /provision")

        $sb.Append(" /domain $Domain")
        $sb.Append(" /machine $MachineName")

        $tempFile = [System.IO.Path]::GetTempFileName()
        $sb.Append(" /savefile $tempFile")
        
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
            $sb.Append("djoin.exe /requestodj")
            $sb.Append(" /loadfile $tempFile")
            $sb.Append(" /windowspath $WindowsPath")
            $sb.Append(" /localos")

            $djoinResult = Invoke-Expression -Command $sb.ToString()
            if ($djoinResult -notlike "*successfully*") {
                Write-Error `
                        -Message "Machine $MachineName failed to provision. DJoin output: $djoinResult" `
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
    param(
        [string]$ParentPath,
        [string]$Name
    )

    $regItem = Get-ChildItem -Path $ParentPath | `
        Where-Object { $_.PSChildName -eq $Name }
    
    if ($null -eq $regItem) {
        New-Item -Path ($ParentPath + "\" + $Name) | `
            Out-Null
    }
}

function New-RegistryItemProperty {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    $regItemProperty = Get-ItemProperty -Path $Path | `
        Where-Object { $_.Name -eq $Name }
    
    if ($null -eq $regItemProperty) {
        New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value 1 | `
            Out-Null
    } else {
        Set-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value 1 | `
            Out-Null
    }
}

function Get-ADUserObjectPermissions {

}

function Resolve-DnsNameInternal {
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
            Clear-DnsServerCache
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
    param(
        [Parameter(Mandatory=$true)]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Overwrite", 
            "Merge", 
            "Disallow")]
        [string]$ConflictBehavior = "Overwrite"
    )

    $sessionParameters = @{}

    if ($PSBoundParameters.ContainsKey($ComputerName)) {
        $sessionParameters += @{ "ComputerName" = $ComputerName }
    }

    if ($PSBoundParameters.ContainsKey($Credential)) {
        $sessionParameters += @{ "Credential" = $Credential }
    }

    $sessions = New-PSSession @sessionParameters
    
    $output = Invoke-Command `
        -Session $sessions `
        -ArgumentList $DnsForwardingRuleSet, $ConflictBehavior `
        -ScriptBlock {
            $DnsForwardingRuleSet = $args[0]
            $ConflictBehavior = $args[1]

            $rules = $DnsForwardingRuleSet.DnsForwardingRules
            foreach($rule in $rules) {
                $zone = Get-DnsServerZone | `
                    Where-Object { $_.ZoneName -eq $zone.DomainName }

                $masterServers = $rule.MasterServers
                if ($null -ne $rule) {
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
                                $masterServers)
                            
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
            }
        }
    
    return $output
}

function Push-OnPremDnsServerConfiguration {
    param(
        [Parameter(Mandatory=$true)]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.HashSet[string]]$AzDnsForwarderIpAddress,

        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.HashSet[string]]$DnsServerNames,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Overwrite", 
            "Merge", 
            "Disallow")]
        [string]$ConflictBehavior = "Overwrite"
    )
    
    $sessionParameters = @{ "ComputerName" = $DnsServerNames }
    if ($PSBoundParameters.ContainsKey($Credential)) {
        $sessionParameters += @{ "Credential" = $Credential }
    }

    $sessions = New-PSSession @sessionParameters

    $output = Invoke-Command `
        -Session $sessions `
        -ArgumentList $DnsForwardingRuleSet, $AzDnsForwarderIpAddress, $ConflictBehavior `
        -ScriptBlock {
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
    
    return $output
}

function New-AzDnsForwarder {
    param(
        [string]$DnsServerResourceGroupName,
        [string]$VirtualNetworkResourceGroupName,
        [string]$VirtualNetworkName,
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
        Write-Error -Message "Virtual network $virtualNetworkName does not exist in resource group $virtualNetworkResourceGroupName."
    }

    # Verify virtual network's subnet. 
    $virtualNetworkSubnet = $virtualNetwork | `
        Select-Object -ExpandProperty Subnets | `
        Where-Object { $_.Name -eq $virtualNetworkSubnetName } 

    if ($null -eq $virtualNetworkSubnet) {
        Write-Error -Message "Subnet $virtualNetworkSubnetName does not exist in virtual network $virtualNetworkName."
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
        $domain = Get-ADDomainInternal
    } else {
        try {
            $domain = Get-ADDomainInternal -Identity $DomainToJoin
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
        Select-Object @{ 
                Name = "Incrementor"; 
                Expression = { $intCaster.Invoke($_.DNSHostName, $DnsForwarderRootName, $domain.DNSRoot) } } | `
        Select-Object -ExpandProperty Name | `
        Measure-Object -Maximum | `
        Select-Object -ExpandProperty Maximum
    
    if ($currentIncrementor -lt 1000) {
        $currentIncrementor++
    }

    # Register new DNS servers for offline domain join
    if ($DnsForwarderRedundancyCount -ne 2) {
        throw [System.NotImplementedException]::new("Only exactly 2 forwarders are supported.")
    }

    $dnsForwarderNames = [string[]]@()
    for($i = $currentIncrementor; $i -lt $DnsForwarderRedundancyCount; $i++) {
        $dnsForwarderNames += ($DnsForwarderRootName + "-" + $i)
    }
    
    $odjBlobs = $dnsForwarderNames | Register-OfflineMachine -Domain $DomainToJoin
    
    ## Encode ruleset
    $encodedDnsForwardingRuleSet = $DnsForwardingRuleSet | ConvertFrom-EncodedJson -Depth 3

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
        Restart-AzVM -ResourceGroupName $DnsServerResourceGroupName -Name $dnsForwarder
    }

    if ($null -eq $OnPremDnsHostNames) {
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

        $onPremDnsServers = Resolve-DnsNameInternal -Name $domain.DNSRoot | `
            Where-Object { $_.Type -eq "A" } | `
            Select-Object -ExpandProperty IPAddress
    } else {
        $onPremDnsServers = $OnPremDnsHostNames | `
            Resolve-DnsNameInternal | `
            Where-Object { $_.Type -eq "A" } | `
            Select-Object -ExpandProperty IPAddress
    }

    Push-OnPremDnsServerConfiguration `
            -DnsForwardingRuleSet $DnsForwardingRuleSet `
            -AzDnsForwarderIpAddress $dnsForwarder0PrivateIp, $dnsForwarder0PrivateIp `
            -DnsServerNames $onPremDnsServers `
            -Credential $Cred
    
    Clear-DnsClientCacheInternal
}

Export-ModuleMember -Function `
    "New-AzDnsForwarder",
    "New-AzDnsForwardingRuleSet",
    "Add-AzDnsForwardingRule",
    "Register-OfflineMachine",
    "Join-OfflineMachine",
    "ConvertFrom-EncodedJson",
    "ConvertTo-EncodedJson",
    "New-RegistryItem",
    "New-RegistryItemProperty",
    "Push-AzDnsServerConfiguration",
    "Push-OnPremDnsServerConfiguration"