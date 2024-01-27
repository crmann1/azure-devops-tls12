# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.Synopsis
    Analysis of TLS 1.2 and TLS 1.3 compatibility for Visual Studio.

.Description
    This script aims to help customers in analyze TLS related errors when using Visual Studio.
    The script performs read-only analysis, does not execute any mitigations.
    The script runs on Windows client / server OS and detects well-known causes of TLS 1.2 and cipher suite incompatibilities.
    Lowest OS version where this script has been tested on: Windows Server 2008 R2.
#>

$version = "2024-1-27"

#EndpointsToCheck
$endpointsToCheck = "status.dev.azure.com","app.vssps.visualstudio.com","go.microsoft.com","login.microsoftonline.com","management.azure.com","graph.windows.net","graph.microsoft.com","management.core.windows.net","api.vstsusers.visualstudio.com"


function Main()
{
    Write-Detail "Visual Studio TLS v.$version"

    $osVersion = GetOSInfo
    Write-Break
   
    EnumSSLRegKey
    Write-Break

    Write-Title "Enumerating Machine ciphers"
    GetAllCiphers

    Write-Title "Probing Sites commonly used by Visual Studio"
    $endpointsToCheck.GetEnumerator() | ForEach-Object {
        $domain = $_
        Write-Info "========== Probing: $domain =========="
        Write-Host "==========System Default TLS=========="
        Probe $domain 0
        Write-Host "==========TLS 1.2=========="
        Probe $domain 3072
        Write-Host "==========TLS 1.3=========="
        Probe $domain 12288
        Write-Info "========== Finished Probing: $domain =========="
        Write-Host "`n"
        Write-Host "`n"
    }
}

function Write-OK { param($str) Write-Host -ForegroundColor green $str } 
function Write-nonOK { param($str) Write-Host -ForegroundColor red $str } 
function Write-Warning { param($str) Write-Host -ForegroundColor magenta $str } 
function Write-Info { param($str) Write-Host -ForegroundColor yellow $str } 
function Write-Detail { param($str) Write-Host -ForegroundColor gray $str } 
function Write-Break { Write-Host -ForegroundColor Gray "********************************************************************************" }
function Write-Title 
{
    param($str)
    Write-Host -ForegroundColor Yellow ("=" * ($str.Length + 4))
    Write-Host -ForegroundColor Yellow "| $str |" 
    Write-Host -ForegroundColor Yellow ("=" * ($str.Length + 4))
} 

function GetAllCiphers()
{
    if ($osVersion.Major -ge 10) 
    {
        $allenabledResult = Get-TlsCipherSuite
        $tls12protocolCode = 771
        $tls13protocolCode = 772
        $tls12EnabledCipherSuites = $allenabledResult | & {
            process {
                if (($_.Protocols | Where-Object { $_ -eq $tls12protocolCode }).Count -gt 0) { $_.Name}
            }
        }

        $tls13EnabledCipherSuites = $allenabledResult | & {
            process {
                if (($_.Protocols | Where-Object { $_ -eq $tls13protocolCode }).Count -gt 0) { $_.Name}
            }
        }

        Write-Detail "All TLS12 cipher suites:"
        Write-Detail $tls12EnabledCipherSuites | Out-String

        Write-Detail "All TLS13 cipher suites:"
        Write-Detail $tls13EnabledCipherSuites | Out-String
    }
}

function TryToSecureConnect
{
    param($connectHost, $sslprotocolcode)
    $client = New-Object Net.Sockets.TcpClient
    try 
    {        
        try 
        {
            $client.Connect($connectHost, 443) # if we fail here, it is not SSL/TLS issue
        } 
        catch # case of network/DNS error (no TLS problem)
        {
            return $null
        }
        $stream = New-Object Net.Security.SslStream $client.GetStream(), $true, ([System.Net.Security.RemoteCertificateValidationCallback]{ $true })
        $remoteEndpoint = $client.Client.RemoteEndPoint
        try
        {
            $askedProtocols = [System.Security.Authentication.SslProtocols]($sslprotocolcode) # TLS 1.2
            $stream.AuthenticateAsClient($connectHost, $null, $askedProtocols, $false)
            return ($true, $remoteEndpoint, $null)
        }
        catch [System.IO.IOException],[System.ComponentModel.Win32Exception] # case of failed TLS negotation
        {
            # Seen exceptions here:
            #   Error: The client and server cannot communicate, because they do not possess a common algorithm.
            #   Error: Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host.

            return ($false, $remoteEndpoint, $_)
        }        
        finally {$stream.Dispose()}
    }
    finally 
    {
        $client.Dispose()
    }    
}

# Probe a domain and print out any errors
function Probe
{
    param ($domain, $sslprotocolcode)

  ($success, $remoteAddress, $handshakeException) = TryToSecureConnect $domain $sslprotocolcode
    switch ($success)
    {
        $null { Write-nonOK "Failed to reach the destination. This is connectivity or DNS problem, *not* TLS compatibility issue." }
        $true { Write-OK "Probe succeeded. Connection negotiated successfully to $remoteAddress" }
        $false 
        {
             Write-nonOK "ISSUE FOUND: This may be TLS compatibility issue!"
             Write-nonOK  "Probe failed when TLS-negotiating to $remoteAddress. Error: $handshakeException"         
        }
    } 
}


function EnumSSLRegKey
{
  Write-Host "Enablement Keys HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

  $keys = Get-ChildItem -Path  HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols -Recurse

  # Loop through each key and print its item properties
  foreach ($key in $keys) {
    Write-Host "Key: $($key.PSPath)"
    $item = Get-ItemProperty -Path $key.PSPath | Select-Object * -Exclude PS*
    Write-Host $item
  }
}


function GetOSInfo
{
    Write-Detail "Getting environment info..."

    $envOsVersion = [System.Environment]::OSVersion.Version # if OS went through update (W8 -> W8.1 -> W10 ...), this may return pre-update version (https://stackoverflow.com/questions/33328739/system-environment-osversion-returns-wrong-version) 
    $winVersionRex = "([0-9]+\.)+[0-9]+"
    $systemInfoVersion = $null
    if ((systeminfo /fo csv | ConvertFrom-Csv | Select-Object -Property "OS Version")."OS Version" -match $winVersionRex) { $systemInfoVersion = [version]$Matches[0] } # systeminfo command is considered obsolete but gives up to date version
    $osVersion = if ($envOsVersion -gt $systemInfoVersion) { $envOsVersion } else { $systemInfoVersion } # Take the highest OS version seen

    Write-Host "PS Version:" $PSversionTable.PSVersion
    Write-Host "PS Edition: " $PSversionTable.PSEdition
    Write-Host "CLR Version: " $PSversionTable.CLRVersion
    Write-Host "OS Version: system.environment: $envOsVersion, systeminfo: $systemInfoVersion --> $osVersion"
    return $osVersion
}

Main