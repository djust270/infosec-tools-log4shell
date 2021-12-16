# Parse IIS logs for Log4Shell attempts
# Logs will be dumped to C:\temp\log4shellAttempts.txt
mkdir C:\temp
$logs = gci "C:\inetpub\logs\LogFiles\W3SVC1" -file -recurse 
$content = $logs | foreach {get-content $_.fullname}
$content | select-string -simplematch "jndi" | out-file C:\temp\log4shellAttempts.txt -append
$content | select-string -simplematch 'lower' | out-file C:\temp\log4shellAttempts.txt -append
$content | select-string -simplematch 'upper' | out-file C:\temp\log4shellAttempts.txt -append
$content | select-string -simplematch '${' | out-file C:\temp\log4shellAttempts.txt -append
& "C:\temp\log4shellAttempts.txt"



 
