param(
    [string]$OdjBlob,
    [string]$TempUser,
    [switch]$SkipUserDisable
)

Import-Module .\AzureFilesArmUtilities.psm1

Install-WindowsFeature `
        -Name "FS-DFS-Namespace" | `
    Out-Null

$path = Get-Location | Select-Object -ExpandProperty Path
$dnsForwarderOdj = [System.IO.Path]::Combine($path, "dfsn.odj")
$djOutput = [System.IO.Path]::Combine($path, "djOutput.txt")

Write-OdjBlob -OdjBlob $OdjBlob -Path $dnsForwarderOdj
Join-WindowsMachine `
    -OdjBlobPath $dnsForwarderOdj `
    -WindowsPath $env:windir `
    -JoinOutputPath $djOutput

if (!$SkipUserDisable) {
    Disable-LocalUser -Name $TempUser
}