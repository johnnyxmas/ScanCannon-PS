<#
.SYNOPSIS
    ScanCannon: a program to enumerate and parse a large range of public networks, primarily for determining potential attack vectors
.DESCRIPTION
    This script takes a CIDR range or a file containing line-separated CIDR ranges as input and performs a series of scans using masscan and nmap. It then generates reports on the discovered hosts, ports, and services.
.PARAMETER InputArg
    A CIDR range or a file containing line-separated CIDR ranges.
.PARAMETER UDPScan
    Perform UDP scan on common ports (53, 161, 500) using nmap.
.EXAMPLE
    .\scancannon.ps1 192.168.0.0/24
    Scans the 192.168.0.0/24 CIDR range.
.EXAMPLE
    .\scancannon.ps1 ranges.txt
    Scans the CIDR ranges specified in the ranges.txt file.
.EXAMPLE
    .\scancannon.ps1 192.168.0.0/24 -UDPScan
    Scans the 192.168.0.0/24 CIDR range and performs a UDP scan on common ports.
#>
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$InputArg,
    [switch]$UDPScan
)

# Configuration
$LogFile = "scancannon.log"
$ScanCannonConfig = "scancannon.conf"

# Logging
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    $LogMessage | Out-File -FilePath $LogFile -Append
    Write-Host $LogMessage
}

# Display banner
Clear-Host
Write-Host "███████╗ ██████╗ █████╗ ███╗   ██╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗ ██████╗ ███╗   ██╗"
Write-Host "██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔═══██╗████╗  ██║"
Write-Host "███████╗██║     ███████║██╔██╗ ██║██║     ███████║██╔██╗ ██║██╔██╗ ██║██║   ██║██╔██╗ ██║"
Write-Host "╚════██║██║     ██╔══██║██║╚██╗██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██║   ██║██║╚██╗██║"
Write-Host "███████║╚██████╗██║  ██║██║ ╚████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║╚██████╔╝██║ ╚████║"
Write-Host "╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝"
Write-Host "••¤(×[¤ ScanCannon v1.0 by J0hnnyXm4s ¤]×)¤••`n"

# Check for updates
try {
    $RemoteLastWriteTime = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/johnnyxmas/scancannon-ps/main/scancannon.ps1" -Method Head -ErrorAction Stop).Headers.'Last-Modified'
    $RemoteLastWriteTime = [DateTime]::ParseExact($RemoteLastWriteTime, "R", [System.Globalization.CultureInfo]::InvariantCulture)
    $LocalLastWriteTime = (Get-Item ".\scancannon.ps1").LastWriteTime

    if ($RemoteLastWriteTime -gt $LocalLastWriteTime) {
        $UpdateChoice = Read-Host "A new version of ScanCannon is available. Do you want to update? [y/N]"
        if ($UpdateChoice -eq "y" -or $UpdateChoice -eq "Y") {
            try {
                Invoke-Expression "git pull origin main"
                Write-Log "ScanCannon has been updated successfully." -Level Info
            }
            catch {
                Write-Log "Failed to update ScanCannon via git. Please manually download the latest version from https://github.com/johnnyxmas/scancannon-ps" -Level Warning
            }
        }
        else {
            Write-Log "Update skipped. Continuing with the current version." -Level Info
        }
    }
}
catch {
    Write-Log "Failed to check for updates. Please check your internet connection and try again." -Level Warning
}

# Help Text
function Show-HelpText {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
}

# Check if required tools are installed
$RequiredTools = @("masscan", "nmap")
foreach ($Tool in $RequiredTools) {
    if (-not (Get-Command $Tool -ErrorAction SilentlyContinue)) {
        Write-Log "ERROR: $Tool is not installed. Please install it and try again." -Level Error
        exit 1
    }
}

# Parse command line options
$UDPScan = $UDPScan.IsPresent

# Make sure an argument is supplied
if ([string]::IsNullOrWhiteSpace($InputArg)) {
    Write-Log "ERROR: Invalid argument(s)." -Level Error
    Show-HelpText
    exit 1
}

# Check if the argument is a valid CIDR range or a file
if ($InputArg -match '^([0-9]{1,3}\.){3}[0-9]{1,3}(/(3[0-2]|[12]?[0-9]))?$') {
    $CIDRRanges = @($InputArg)
}
elseif (Test-Path $InputArg -PathType Leaf) {
    $CIDRRanges = Get-Content $InputArg
}
else {
    Write-Log "ERROR: Invalid CIDR range or file." -Level Error
    Show-HelpText
    exit 1
}

# Check for administrator privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Log "ERROR: This script must be run as an administrator" -Level Error
    Show-HelpText
    exit 1
}

# Check if scancannon.conf exists
if (-not (Test-Path $ScanCannonConfig -PathType Leaf)) {
    Write-Log "ERROR: $ScanCannonConfig not found. Please make sure it exists in the current directory." -Level Error
    exit 1
}

# Alert for existing Results files
if (Test-Path ".\results") {
    $Reply = Read-Host "Results folder exists. New results will be combined with existing. Re-scanning previous subnets will overwrite some files. Proceed? [y/N]"
    if ($Reply -notmatch '^[Yy]$') {
        exit 1
    }
}
else {
    New-Item -ItemType Directory -Path ".\results" | Out-Null
}

# Download and prep the latest list of TLDs from IANA
if (Test-Path ".\all_tlds.txt") {
    Remove-Item ".\all_tlds.txt"
}
try {
    Invoke-WebRequest -Uri "https://data.iana.org/TLD/tlds-alpha-by-domain.txt" -OutFile ".\all_tlds.txt" -ErrorAction Stop
    (Get-Content ".\all_tlds.txt") -replace '^', '\.' | Out-File ".\all_tlds.txt"
}
catch {
    Write-Log "ERROR: Failed to download TLD list. Please check your internet connection and try again." -Level Error
    exit 1
}

# Initialize variables for summary
$TotalIPs = 0
$ResponsiveIPs = 0
$DiscoveredServices = 0

# Handle Ctrl+C
[Console]::TreatControlCAsInput = $true
$CancelEvent = Register-ObjectEvent -InputObject ([Console]::TreatControlCAsInput) -EventName CancelKeyPress -Action {
    Write-Log "`n`n[!] Ctrl+C detected. Cleaning up..." -Level Warning
    Cleanup
    Write-Log "Exiting." -Level Info
    exit 0
}

# Process each CIDR range
foreach ($CIDR in $CIDRRanges) {
    Write-Log "Scanning $CIDR..." -Level Info
    
    # Make results directories named after subnet
    $DirName = $CIDR -replace "/", "_"
    Write-Log "Creating results directory for $CIDR. . ." -Level Info
    New-Item -ItemType Directory -Path ".\results\$DirName" -Force | Out-Null
    
    # Start Masscan. Write to binary file so users can --readscan it to whatever they need later
    Write-Log "`n*** Firing ScanCannon. Please keep arms and legs inside the chamber at all times ***" -Level Info
    $MasscanCommand = "masscan -c $ScanCannonConfig --open --source-port 40000 -oB `".\results\$DirName\masscan_output.bin`" $CIDR"
    Write-Log "Running command: $MasscanCommand" -Level Info
    Invoke-Expression $MasscanCommand
    $ReadscanCommand = "masscan --readscan `".\results\$DirName\masscan_output.bin`" -oL `".\results\$DirName\masscan_output.txt`""
    Write-Log "Running command: $ReadscanCommand" -Level Info
    Invoke-Expression $ReadscanCommand
    
    # Update total IPs scanned
    $TotalIPs += [Math]::Pow(2, 32 - [int]($CIDR -split "/")[1])
    
    if (-not (Test-Path ".\results\$DirName\masscan_output.txt")) {
        Write-Log "`nNo IPs are up; skipping nmap. This was a big waste of time.`n" -Level Warning
        continue
    }
    
    # Consolidate IPs and open ports for each IP
    $HostsAndPorts = Get-Content ".\results\$DirName\masscan_output.txt" |
    Select-String -Pattern "open" |
    ForEach-Object {
        $IP = $_.Line.Split()[3]
        $Port = $_.Line.Split()[2]
        "$IP`:$Port"
    }
    $HostsAndPorts | Out-File ".\results\$DirName\hosts_and_ports.txt"
    
    # Update responsive IPs count
    $ResponsiveIPs += ($HostsAndPorts | ForEach-Object { $_.Split(':')[0] } | Select-Object -Unique).Count
    
    # Run in-depth nmap enumeration against discovered hosts & ports, and output to all formats
    # First, we have to do a blind UDP nmap scan of common ports, as masscan does not support UDP. Note we Ping here to reduce scan time.
    if ($UDPScan) {
        Write-Log "`nStarting DNS, SNMP and VPN scan against all hosts" -Level Info
        $UDPScanCommand = "nmap -v --open -sV --version-light -sU -T3 -p 53,161,500 -oA `".\results\$DirName\nmap_${DirName}_udp`" $CIDR"
        Write-Log "Running command: $UDPScanCommand" -Level Info
        Invoke-Expression $UDPScanCommand
    }
    
    # Then nmap TCP against masscan-discovered hosts
    $TotalHosts = $HostsAndPorts.Count
    $CurrentHost = 0
    foreach ($Target in $HostsAndPorts) {
        $IP = $Target.Split(':')[0]
        $Port = $Target.Split(':')[1]
        $FileName = "nmap_$IP"
        Write-Log "`nBeginning in-depth TCP scan of $IP on port(s) $Port:`n" -Level Info
        $TCPScanCommand = "nmap -v --open -sV --version-light -sT -O -Pn -T3 -p $Port -oA `".\results\$DirName\$FileName`_tcp`" $IP"
        Write-Log "Running command: $TCPScanCommand" -Level Info
        Invoke-Expression $TCPScanCommand
        
        # Update progress bar
        $CurrentHost++
        $Progress = [int]($CurrentHost * 100 / $TotalHosts)
        Write-Progress -Activity "Scanning hosts" -Status "$Progress% Complete:" -PercentComplete $Progress
    }
    Write-Progress -Activity "Scanning hosts" -Status "100% Complete:" -PercentComplete 100 -Completed
    
    # Generate lists of Hosts:Ports hosting Interesting Services™️ for importing into cred stuffers (or other tools)
    New-Item -ItemType Directory -Path ".\results\$DirName\interesting_servers" -Force | Out-Null
    New-Item -ItemType Directory -Path ".\results\all_interesting_servers" -Force | Out-Null
    
    $InterestingServices = @("domain", "msrpc", "snmp", "netbios-ssn", "microsoft-ds", "isakmp", "l2f", "pptp", "ftp", "sftp", "ssh", "telnet", "http", "ssl", "https")
    foreach ($Service in $InterestingServices) {
        $Result = Select-String -Path ".\results\$DirName\*.gnmap" -Pattern "$Service/.+/.+\d+/open/.+/$Service" -AllMatches
        if ($Result) {
            $ServIP = ($Result.Matches.Value | ForEach-Object { $_.Split()[1] }) -join ","
            $ServPort = ($Result.Matches.Value | ForEach-Object { $_.Split('/')[2] }) -join ","
            "$ServIP`:$ServPort" | Out-File -Append ".\results\$DirName\interesting_servers\${Service}_servers.txt"
            "$ServIP`:$ServPort" | Out-File -Append ".\results\all_interesting_servers\all_${Service}_servers.txt"
            $DiscoveredServices++
        }
    }
    
    # Generate list of discovered sub/domains for this subnet.
    "Root Domain,IP,CIDR,AS#,IP Owner" | Out-File ".\results\$DirName\resolved_root_domains.csv"
    "Root Domain,IP,CIDR,AS#,IP Owner" | Out-File -Append ".\results\all_root_domains.csv"
    
    Get-Content ".\all_tlds.txt" | ForEach-Object {
        $TLD = $_
        Select-String -Path ".\results\$DirName\*.gnmap" -Pattern "$TLD" -AllMatches |
        ForEach-Object { $_.