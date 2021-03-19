
# ================= Global API Declaration Area =================

$ApiKey_VT=''
$ApiKey_AbuseIPDB=''
#$APIKey_WhoisXML=''
#$APIKey_Ipinfo=''

# ===============================================================
function Search-VirusTotal-Web { # Search VirusTotal for Web Matches
	
	Param($query)
	$url="https://www.virustotal.com/vtapi/v2/url/report?apikey=$ApiKey_VT&resource=$query"
	$httpResponse = Invoke-RestMethod -uri $url
	Write-Host
	Write-Host '   VirusTotal Data:'
	Write-Host
	if ($httpResponse.response_code -eq 0) {
		Show-Error ('Data not found')
		Return
	}
	Write-Host '   URL . . . . . . . . . . . . . :'$httpResponse.url
	if ($httpResponse.positives -gt 0 ) { 
		$ReportMessage = '   Detections. . . . . . . . . . : '+$httpResponse.positives+'/'+$httpResponse.total
		Write-Host -ForegroundColor Red $ReportMessage
	} else {
		$ReportMessage = '   Detections. . . . . . . . . . : 0/'+$httpResponse.total
		Write-Host -ForegroundColor Green $ReportMessage
	}
	Write-Host
	
	foreach($scan in $httpResponse.scans.psobject.Properties) {

		if ($scan.Value.'detected' -eq 'True') {
			$ReportMessage = '   '+$scan.name+(' '*(30-$scan.name.Length))+': '+$scan.Value.'result'
			Write-Host -ForegroundColor Red $ReportMessage
		} else{
			$ReportMessage = '   '+$scan.name+(' '*(30-$scan.name.Length))+': Undetected'
			Write-Host -ForegroundColor Green $ReportMessage
		}
	}
	Write-Host
} # End of function Search-VirusTotal-Web

function Search-VirusTotal-Hash { # Search VirusTotal for File Hash Matches

	Param($query)
	$url="https://www.virustotal.com/vtapi/v2/file/report?apikey=$ApiKey_VT&resource=$query"
	$httpResponse = Invoke-RestMethod -uri $url
	Write-Host
	Write-Host '   VirusTotal Data:'
	Write-Host

	if ($httpResponse.response_code -eq 0) {
		Show-Error ('Data not found')
		Return
	}

	Write-Host '   MD5 . . . . . . . . . . . . . :'$httpResponse.md5
	Write-Host '   SHA1. . . . . . . . . . . . . :'$httpResponse.sha1
	Write-Host '   SHA256. . . . . . . . . . . . :'$httpResponse.sha256

	if ($httpResponse.positives -gt 0 ) { 
		$ReportMessage = '   Detections. . . . . . . . :'+$httpResponse.positives+'/'+$httpResponse.total
		Write-Host -ForegroundColor Red $ReportMessage
	} else {
		$ReportMessage = '   Detections. . . . . . . . . . : 0/'+$httpResponse.total
		Write-Host -ForegroundColor Green $ReportMessage
	}
	Write-Host
	
	foreach($scan in $httpResponse.scans.psobject.Properties) {

		if ($scan.Value.'detected' -eq 'True') {
			$ReportMessage = '   '+$scan.name+(' '*(30-$scan.name.Length))+': '+$scan.Value.'result'+' (Version '+$scan.Value.'version'+' Update '+$scan.Value.'update'+')'
			Write-Host -ForegroundColor Red $ReportMessage
		} else{
			$ReportMessage = '   '+$scan.name+(' '*(30-$scan.name.Length))+': Undetected (Version '+$scan.Value.'version'+' Update '+$scan.Value.'update'+')'
			Write-Host -ForegroundColor Green $ReportMessage
		}
	}
	Write-Host
} # End of function Search-VirusTotal-Hash

function Search-AbuseIPDB { # Search AbuseIPDB for IP Matches
	
	Param($query)
	$body = @{
		ipAddress=$query
		maxAgeInDays=30
	}
	$header = @{
		Key=$ApiKey_AbuseIPDB
	}
	try {
		$httpResponse = Invoke-RestMethod -Method GET -Body $body -Header $header -uri "https://api.abuseipdb.com/api/v2/check"
	} Catch {
		Write-Host
		Write-Host -BackgroundColor DarkRed -ForegroundColor Black '---- Error : Incorrect IP Format ----'
		Write-Host
		Return
	}

	Write-Host
	Write-Host '   AbuseIPDB Data:'
	Write-Host
	Write-Host '   IP Address. . . . . . . . . . :'$httpResponse.data.ipAddress
	if ($httpResponse.data.abuseConfidenceScore -gt 0) {
		Write-Host -ForegroundColor Red '   Abuse Confidence Score. . . . :'$httpResponse.data.abuseConfidenceScore
	} else {
		Write-Host -ForegroundColor Green '   Abuse Confidence Score. . . . :'$httpResponse.data.abuseConfidenceScore
	}

	Write-Host '   is Public IP. . . . . . . . . :'$httpResponse.data.isPublic
	Write-Host '   Internet Service Provider . . :'$httpResponse.data.isp
	Write-Host '   Usage Type. . . . . . . . . . :'$httpResponse.data.usageType
	Write-Host '   Associated Domains. . . . . . :'$httpResponse.data.domain
	Write-Host '   Country . . . . . . . . . . . :'$httpResponse.data.countryCode
	Write-Host '   Total Reports (30 days) . . . :'$httpResponse.data.totalReports
	Write-Host '   Last Reported on. . . . . . . :'$httpResponse.data.lastReportedAt
	Write-Host

} # End of function Search-AbuseIPDB

function Show-Help {

	Write-Host
	Write-Host -ForegroundColor Yellow 'This Tool Searches Threat Intelligence Feeds'
	Write-Host
	Write-Host -ForegroundColor Yellow '-h  --help      Print this help message'
	Write-Host -ForegroundColor Yellow '-i  --input     Loads a file and searches for all its items'
	Write-Host -ForegroundColor Yellow '                *Supported Formats (.txt, .csv)'
	Write-Host -ForegroundColor Yellow '-o  --output    Save the search results to a file'
	Write-Host -ForegroundColor Yellow '                *Supported Formats (.txt, .csv, .html)'
	Write-Host -ForegroundColor Yellow '-v  --verbose   Show verbose search results'
	Write-Host
	Write-Host -ForegroundColor Yellow 'Sample Usage:   > TISearch.ps1 https://www.google.com'
	Write-Host -ForegroundColor Yellow 'Sample Usage:   > TISearch.ps1 8.8.8.8'
	Write-Host -ForegroundColor Yellow 'Sample Usage:   > TISearch.ps1 b10a8db164e0754105b7a99be72e3fe5'
	Write-Host

} # function Show-Help

function Show-Error {

	Param ($ErrorMessage)
	Write-Host
	Write-Host -ForegroundColor Red '   Error :' $ErrorMessage
	Write-Host -ForegroundColor Red '   Use <-h> or <--help> to show help '
	Write-Host
	
} # End of function Show-Error

function Search-IP {

	Param ($query)
	Search-AbuseIPDB($query)
	Search-VirusTotal-Web($query)
	Exit
}

function Search-URL {

	Param ($query)
	Search-VirusTotal-Web($query)
	Exit
}

function Search-Hash {

	Param ($query)
	Search-VirusTotal-Hash($query)
	Exit

}
function Initialize-Argument {

	Param([array]$LocalArgs)
	function isIP {
		Param($SearchArgument)
		return [boolean]($SearchArgument -as [ipaddress])
	} # End of isIP

	function isURL { # isURL will return true for IP, but not vice versa. So do isIP first.
		Param($SearchArgument)
		return [boolean](($SearchArgument.Substring(0,7) -eq 'http://') -or ($SearchArgument.Substring(0,8) -eq 'https://'))
	} # End of isURL
	
	function isHash {
		Param($SearchArgument)
		$HashChars = @('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f')
		if ($SearchArgument.Length -in @(32,40,64)) {
			for ($i=0; $i -lt $SearchArgument.Length; $i++) {
				if ( -not ($SearchArgument.Substring($i,1) -in $HashChars)) {
					return $false
				}
			}
		} else {
			return $false
		}
		return $true
	} # End of isHash

	# ================================ Argument Parsing  ================================
	
	#$isVerbose=$false

	for ($i=0; $i -lt $LocalArgs.Length; $i++) { # Iterate through all arguments 
		
		if (($LocalArgs[$i].Substring(0,1) -eq '-') -or ($LocalArgs[$i].Substring(0,2) -eq '--')) { # Check if Argument is operator (- or --)
			
			switch ($LocalArgs[$i]){ # Operator Parsing

				'-h' {
					Show-Help
					Exit
				}
				'--help' {
					Show-Help
					Exit
				}
				'-i' {
					Write-Host -ForegroundColor Red 'Input Function in Development, Exiting...'
					Exit
				}
				'--input' {
					Write-Host -ForegroundColor Red 'Input Function in Development, Exiting...'
					Exit
				}
				'-o' {
					Write-Host -ForegroundColor Red 'Output Function in Development, Exiting...'
					Exit
				}
				'--output'{
					Write-Host -ForegroundColor Red 'Output Function in Development, Exiting...'
					Exit
				}
				'-v'{
					#$isVerbose=$true
				}
				'--verbose' {
					#$isVerbose=$true
				}
				default {
					$ErrorMessage = 'This command is not valid : '+$LocalArgs[$i]
					Show-Error($ErrorMessage)
					Exit
				}
			}
		} else { # Check if Argument is IP, URL or Hash

			if (isIP($LocalArgs[$i])) { # Search IP
				Search-IP($LocalArgs[$i])
			} elseif (isURL($LocalArgs[$i])) { # Search URL
				Search-URL($LocalArgs[$i])
			} elseif (isHash($LocalArgs[$i])) { # Search Hash
				Search-Hash($LocalArgs[$i])
			} else {
				$ErrorMessage = 'This argument is not valid : '+$LocalArgs[$i]
				Show-Error($ErrorMessage)
				Exit
			} 
		} # End of Checking if Argument is IP, URL or Hash
	} # End of Argument Iteration
} # End of function Initialize-Argument



# ================================ Execution  ================================

Initialize-Argument ($args)

# ============================================================================