<# Powershell Template
.SYNOPSIS
	<Overview of script>

.DESCRIPTION
	<Brief description of script>

.PARAMETER <Parameter_Name>
	<Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
	<Inputs if any, otherwise state None>

.OUTPUTS
	<Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>

.NOTESs
	Version:        1.0
	Author:         Joey Ashley
	Creation Date:  2022-11-07
	Purpose/Change: Initial script development
  
.EXAMPLE
	<Example goes here. Repeat this attribute for more than one example>

.LINK
	https://learn.microsoft.com/en-us/powershell/scripting/samples/collecting-information-about-computers?view=powershell-7.2
#>

<#
#>

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Get-Timestamp { 
	Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }
}

#---------------------------------------------------------[Initializations]--------------------------------------------------------

$hostname = hostname 
$timestamp = Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }
# Set base directory to work in
$base_directory="C:\Temp\MicroAudit\"
#$data_directory=($base_directory + "\Data\" + $timestamp)
$report_directory=($base_directory + "\Reports")
# JSON report file 
$json_report_file = ($report_directory + "\audit-" + $hostname + "-" + $timestamp + ".json")
$csv_report_file = ($report_directory + "\programs-" + $hostname + "-" + $timestamp + ".csv")
# Depth to parse JSON
$depth = 3

## Prepare working directory

# Check if directory exists and otherwise create it, then change to it
if ($(test-path -path $base_directory)) { 
	cd $base_directory; 
} else {
	new-item -type directory -path $base_directory; 
} #cd $base_directory } # Otherwise create it, then change to it

# Create report directory if it doesn't exist
if ( ! $(test-path -path $report_directory)) { new-item -type directory -path $report_directory }

# Create data directory if it doesn't exist
#if ( ! $(test-path -path $data_directory)) { new-item -type directory -path $data_directory }

#Set Error Action to Silently Continue
#$ErrorActionPreference = "SilentlyContinue"

#Dot Source required Function Libraries
#. "C:\Scripts\Functions\Logging_Functions.ps1"


# For whatever reason... Internet explorer needs to have been opened at least once.
Invoke-Item "C:\Program Files\Internet Explorer\iexplore.exe"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

$x=@{}
$x.hostname = $hostname
$x.starttime = Get-Timestamp
$x.pop = @{}
$x.pop.public_ip = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
# https://learn.microsoft.com/en-us/rest/api/maps/geolocation/get-ip-to-location?tabs=HTTP
#$x.pop.geolocation = iwr ("https://atlas.microsoft.com/geolocation/ip/json?api-version=1.0&ip="+$x['pop']['public_ip'])
#$x.connection_test = test-netconnection -computername google.com -traceroute -informationlevel "detailed"
$x.computer_info = get-computerinfo | select *
#$x.programs_mk1 = get-package | select *
#$x.programs_mk2 = Get-WMIObject -Class Win32_Product | select *
$x.programs = Get-WMIObject -Class Win32_Product | select Name,PackageName,Vendor,Version,InstallDate,InstallLocation,InstallSource,IdentifyingNumber,Description,PSComputerName,InstallState
$x.desktop_settings = Get-CimInstance -ClassName Win32_Desktop | select *
$x.bios = Get-CimInstance -ClassName Win32_BIOS | select *
$x.processor = Get-CimInstance -ClassName Win32_Processor | Select-Object -ExcludeProperty "CIM*"
$x.system = Get-CimInstance -ClassName Win32_ComputerSystem
$x.hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering
$x.os_version = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property BuildNumber,BuildType,OSType,ServicePackMajorVersion,ServicePackMinorVersion
$x.local_users = get-localuser | select *
#$x.local_groups = get-localgroups | select *
$x.disk_space = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
$x.session = Get-CimInstance -ClassName Win32_LogonSession
$x.active_user = Get-CimInstance -ClassName Win32_ComputerSystem -Property UserName
$x.local_time = Get-CimInstance -ClassName Win32_LocalTime
$x.services = Get-CimInstance -ClassName Win32_Service | Select-Object -Property Status,Name,DisplayName
$x.password_requirements = net accounts

$ap_csv=auditpol /get /category:* /r
$header=$ap_csv[0] -split ','
$ap_csv = $ap_csv[1..($ap_csv.count - 1)]
$x.auditpol = $ap_csv | ConvertFrom-Csv -Header $header

$x.windows_license = (get-wmiobject -query 'select * from softwarelicensingservice').oa3xoriginalproductkey

$x.net_config = get-netipconfiguration -all
$x.net_connections = get-nettcpconnection -verbose -state "established"
$x.tracert = @{}
$x.tracert."1.1.1.1" = test-netconnection 1.1.1.1 -traceroute #tracert 1.1.1.1
$x.tracert."8.8.8.8" = test-netconnection 8.8.8.8 -traceroute
$x.endtime = get-timestamp

$x | ConvertTo-Json -Depth 3 | out-file -FilePath $json_report_file -Encoding utf8
$x.programs | Export-Csv -NoClobber -NoTypeInformation "$csv_report_file"
