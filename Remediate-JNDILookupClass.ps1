<#	
Detect and remediate JNDI.Lookup files from any JAR files on the system
#>

$7z = "https://www.7-zip.org/a/7za920.zip"
Invoke-WebRequest -Uri $7z -OutFile "$env:TEMP\7z.zip"
expand-archive $env:temp\7z.zip $env:temp
$drives = Get-PSDrive -PSProvider FileSystem
$log4jfilescan = @()
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
	Write-Host "Determining whether any of the $(($log4jfilenames).count) found .jar files are vulnerable to CVE-2021-44228 due to being capable of JNDI lookups..." -ForegroundColor Yellow
	
	$log4jvulnerablefiles = $log4jfilescan | where-object { $_.Fullname -notmatch "spool\\drivers" } | foreach-object {
		#write-host "CHECKING : " $_.Fullname -ForegroundColor Yellow
		select-string "JndiLookup.class" $_.Fullname | where path -notlike "*2.16*" | select-object -exp Path | sort-object -unique
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
	foreach ($file in $log4jvulnerablefiles)
	{
		write-host "Attempting to remove JNDILookup.class from $($file)..."
		Set-ItemProperty $file isReadOnly $false
		$a = & $env:temp\7z\7za.exe l $file
		$a = $a | select-string "jndilookup.class"
		$b = $a.ToString()
		$b = $b.split(' ')
		$b = $b | select -Last 1
		& $env:temp\7z\7za.exe d $file $b -r
	}
}
remove-item "$env:temp\7z" -recurse -force


