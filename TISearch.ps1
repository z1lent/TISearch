
# ================= Global API Declaration Area =================

$ApiKey_VT=''
$ApiKey_AbuseIPDB=''
$APIKey_WhoisXML=''
$APIKey_Ipinfo=''

# ===============================================================
function Search-VirusTotal-Web { # Search VirusTotal for Web Matches
	
	Param($query)
	$url="https://www.virustotal.com/vtapi/v2/url/report?apikey=$ApiKey_VT&resource=$query"
	$httpResponse = Invoke-RestMethod -uri $url
	Write-Host
	Write-Host '   VirusTotal Data:'
	Write-Host
	if ($httpResponse.response_code -eq 0) {
		Write-Host -BackgroundColor DarkRed -ForegroundColor Black '---- Error : URL not found ----'
		Write-Host
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
	
	
}
function Search-VirusTotal-Hash { # Search VirusTotal for File Hash Matches

	Param($query)
	$url="https://www.virustotal.com/vtapi/v2/file/report?apikey=$ApiKey_VT&resource=$query"
	$httpResponse = Invoke-RestMethod -uri $url
	Write-Host
	Write-Host '   VirusTotal Data:'
	Write-Host

	if ($httpResponse.response_code -eq 0) {
		Write-Host -BackgroundColor DarkRed -ForegroundColor Black '---- Error : Hash not found ----'
		Write-Host
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
	
}

function Search-AbuseIPDB {
	
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

}
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
	Write-Host -ForegroundColor Yellow 'Sample Usage:   > TISearch.ps1 www.google.com'
	Write-Host -ForegroundColor Yellow 'Sample Usage:   > TISearch.ps1 8.8.8.8'
	Write-Host -ForegroundColor Yellow 'Sample Usage:   > TISearch.ps1 b10a8db164e0754105b7a99be72e3fe5'
	Write-Host

}
function Show-Error {

	Write-Host
	Write-Host '   ' -NoNewline
	Write-Host -BackgroundColor DarkRed -ForegroundColor Black '---- Error : Incorrect Input Parameters : ----'
	Show-Help
	
}

function Invoke-SearchParam-Check{
	Param([string]$SearchParam)

}

function Initialize-Argument {

	Param([array]$LocalArgs)
	$SearchArgument=0
	$SearchOperators=@('-u','-i','-f','--url','--ip','--file')
	#$ProcessOperators=@('-o','--output','-l','--list')
	$AllOperators=@('-u','-i','-f','--url','--ip','--file','-o','--output','-l','--list')

	# Search Argument Assignment
	# -u --url  >> 1
	# -i --ip   >> 2
	# -f --file >> 3

	Write-Host
	for ($i=0; $i -lt $LocalArgs.Length; $i++) {

		# Detecting unacceptable case (1): More than one search operator found (ie. -u www.google.com -i 1.1.1.1)
		if ($LocalArgs[$i] -in $SearchOperators) { 
			for ($j=$i+1; $j -lt $LocalArgs.Length; $j++) {
				if ($LocalArgs[$j] -in $SearchOperators) {
					Show-Error
					Return
				}
			}
		} # Finished detecting unacceptable case (1) 

		# Detecting unacceptable case (2): More than one argument found after an operator (ie. -u www.google.com www.bing.com)
		
		if ($LocalArgs[$i] -in $AllOperators) {
			if (($i+2 -lt $LocalArgs.Length) -and ( -not ($LocalArgs[$i+2] -in $AllOperators))) {
				Show-Error
				Return
			}
		} # Finished detecting unacceptable case (2)

		Switch ($LocalArgs[$i]) {
			'-u'{
				$SearchArgument 
			}
			'--url'{$SearchArgument = 1}
			'-i'{$SearchArgument = 2}
			'--ip'{$SearchArgument = 2}
			'-f'{$SearchArgument = 3}
			'--file'{$SearchArgument = 3}
			'-l' {$InputParam=$LocalArgs[$i+1]}
			'--list' {$InputParam=$LocalArgs[$i+1]}
			'-o' {$OutputParam=$LocalArgs[$i+1]}
			'--output' {$OutputParam=$LocalArgs[$i+1]}

		}
	
	}

}

function Initialize-Argument-New {

	Param([array]$LocalArgs)
	function isIP {
		Param($SearchArgument)
		return [boolean]($SearchArgument -as [ipaddress])
	} # End of isIP

	function isURL { # isURL will return true for IP, but not vice versa. So do isIP first.
		Param($SearchArgument)
		$SearchArgumentParsed=($SearchArgument -as [System.URI]).AbsoluteURI
		return [boolean]($SearchArgumentParsed -ne '')
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

	# ---------------- Argument Parsing ----------------

	$ProcessOperators = @('-h','--help','-i','--input','-o','--output','-v','--verbose')
	<#	
		-SearchType Assignment
		Undeclared - 0
		IP - 1
		URL - 2
		Hash - 3
	#>
	$SearchType = 0

	<#
		-function Search-Duplicate
	    Called when ProcessOperator is found.
	    Loops through arguments after that ProcessOperator to check if it's called again
	    ie. -i source.txt url.txt  (duplicate)
	#>
	function Search-Duplicate {

		Param([string]$SearchOperator1, [string]$SearchOperator2, [int]$startPos)


	}
	
	for ($i=0; $i -lt $LocalArgs.Length; $i++) {
		if ($LocalArgs[$i] -in $ProcessOperators) {
			
		}

	}

	# ---------------- End of Argument Parsing ---------

	
	

}


# --------------------------- Execution --------------------------->


#Search-VirusTotal-Hash($args[0])
#Search-AbuseIPDB($args[0])
#Search-VirusTotal-Web($args[0])
#Search-Whois($args[0])
#Initialize-Argument($args)
#Initialize-Argument-New($args)
Show-Help


# -----------------------------------------------------------------<

<# -------------------------- Recylcing --------------------------->


foreach ($i in $args) {
	Write-Host $i
}


foreach( $item in $httpResponse.psobject.properties )
{
	$message = $item.name+' '+$item.value
	Write-Host $message
}

-----------------------------------------------------------------#>