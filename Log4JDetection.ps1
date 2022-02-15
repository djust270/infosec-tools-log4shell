<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2021 v5.8.195
	 Created on:   	12/17/2021 4:40 PM
	 Created by:   	Dave Just
	 Organization: 	
	 Filename: Log4JDetection.ps1    	
	===========================================================================
	.DESCRIPTION
		Parse all mounted drives for .Jar files, then examine .Jar files for JNDI lookup class. Gather results and post to a PowerAutomate flow which will load results to an Azure Table.
#>
#List out each logical mounted drive	
$drives = Get-PSDrive -PSProvider FileSystem
$log4jfilescan = @()
	
#Scan each drive for .jar files
foreach ($drive in $drives)
{
		$log4jfilescan += get-childitem $drive.root -file -filter *.jar -rec -force -ea 0
}
if ($log4jfilescan)
{
		$log4jfilenames = ($log4jfilescan).fullname
}
else
{
		$log4jfiles = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - No JAR files detected"
		$log4jvulnerable = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - No JAR files detected"
		$log4jvulnerablefilecount = '-1'
		Write-Host $log4jfiles -ForegroundColor Red
		
}

if (-Not ($log4jfilescan))
{
	$log4jfiles = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') OK - No JAR Files were found on this device"
	$log4jvulnerable = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') OK - No JAR Files were found on this device"
	$log4jvulnerablefilecount = '0'
	
}
else
{
	#Write-Host "Determining whether any of the $(($log4jfilenames).count) found .jar files are vulnerable to CVE-2021-44228 due to being capable of JNDI lookups..." -ForegroundColor Yellow
	
	$log4jvulnerablefiles = $log4jfilescan | where-object { $_.Fullname -notmatch "spool\\drivers" } | foreach-object {
		#write-host "CHECKING : " $_.Fullname -ForegroundColor Yellow
		select-string "JndiLookup.class" $_.Fullname | where { $_.path -notlike "*2.16*" -and $_.Path -notlike "*2.17*" } | select-object -exp Path | sort-object -unique
	}
	
	$log4jvulnerablefilecount = ($log4jvulnerablefiles).count
}

if (-Not ($log4jvulnerablefiles))
{
	$log4jvulnerable = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') OK - 0 Vulnerable JAR files were found"
	write-host "Log4J CVE-2021-44228 Vulnerable Files:`n$log4jvulnerable" -ForegroundColor Green
}
else
{
	Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') WARNING - $log4jvulnerablefilecount Vulnerable JAR file(s) were found" -foregroundcolor Red
	write-host "Log4J CVE-2021-44228 Vulnerable Files:`n$log4jvulnerablefiles" -ForegroundColor Red
	#$log4jvulnerable = $log4jvulnerablefiles -join '<br>'
	
	if ($log4jvulnerablefilecount -gt 1) { $log4jvulnerablefiles = $log4jvulnerablefiles -join ';' }
	# Create custom object to hold details to send to Power Automate flow which will in turn add contents to Azure Table
	$info = [pscustomobject]@{
		Hostname = hostname
		Domain   = (gcim win32_computersystem).domain
		Log4JFiles = $log4jvulnerablefiles
		FileCount = $log4jvulnerablefilecount
	}
	# Trigger PowerAutomate flow with Invoke-RestMethod. POST content of $info variable to PowerAutomate
	$flow = 'https://prod-141.westus.logic.azure.com:443/workflows/#PathTOPowerAutomteFlowURL'
	$flowheader = $info | ConvertTo-Json -Compress
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
	Invoke-RestMethod -Method Post -Body $flowheader -uri $flow -ContentType "application/json"
}

