# TISearch
TISearch is a PowerShell script which automatically detects search request types, and queries URLs, IPs and hashes on multiple threat intelligence databases. **!** *Please note this tool is currently in development; not all features are available and you may encounter some issues.*

### Usage

Download TISearch.ps1 to local folder

You can query an URL, an IPs or a hash by passing an it to the PowerShell script.

```
> TISearch.ps1 http://www.google.com
> TISearch.ps1 8.8.8.8
> TISearch.ps1 8a2122e8162dbef04694b9c3e0b6cdee
```

> To search an URL, please start with http:// or https://
>
> Supported hash formats are md5, sha1 and sha256.

### Requirements

TISearch relies on a variety of threat intelligence database **API keys** to function properly. The selected databases offer **free** API query services.

**For license compliance, I am not at liberty to share my API keys.** All that is required for you is to create your personal accounts on these services. Please follow the below guide to do so.

After getting the API Keys, please look to the top 10 lines of the script and paste them into the corresponding variable.

```
# ================= Global API Declaration Area =================

$ApiKey_VT=''
$ApiKey_AbuseIPDB=''
#$APIKey_WhoisXML=''
#$APIKey_Ipinfo=''

# ===============================================================
```

#### Getting API Keys

##### VirusTotal

https://developers.virustotal.com/reference

> In order to use the API you must [sign up to VirusTotal Community](https://www.virustotal.com/#/join-us). Once you have a valid VirusTotal Community account you will find your personal API key in your personal settings section. This key is all you need to use the VirusTotal API.

##### AbuseIPDB

https://www.abuseipdb.com/api.html

> After [registering](https://www.abuseipdb.com/register), you can get your API key from the [accounts page](https://www.abuseipdb.com/account). Click on the "API Settings" tab to see your API key. You can generate a new API key at anytime. When you generate a new API key the old key will stop working immediately.

##### WhoisXML

https://whois.whoisxmlapi.com/documentation/making-requests

> Register at https://www.whoisxmlapi.com/ and get your personal API KEY on [My products](https://user.whoisxmlapi.com/products) page.

##### Ipinfo.io

https://ipinfo.io/developers

> Register at https://ipinfo.io/ and get your personal API Key on [Access Token](https://ipinfo.io/account/token) page.



