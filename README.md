# Safe Browsing Check
Splunk app for scanning an url against Googles Safe Browsing API

Info about the Google API: https://developers.google.com/safe-browsing/

The service checks an url and returns either ok, phishing or malware. To test the app you can use the provided csv file.

The splunk query is on the following format:
```
index=<index_name> | table <name_of_url_field> | sb field=<name_of_url_field>
```
##Example search with input data from example csv file:
```
index="phishing" | rename "Phish URL" as url | table url | sb field="url"'
```
This will return a result with the following fields:
- sb_code: result code from Google SB API (200, 204, 400, 401, 503)
- sb_message: result message (phishing, malware, unwanted, nothing found)

To use the service you need an API key from Google Developers Console.

Configuration

in sb.conf file add API key and HTTP proxy settings

##Installation
1. Download the project
2. Update configuration as necessary
3. Create tar archive of main folder (safe_browsing_check)
4. Install in Splunk
5. Done!
