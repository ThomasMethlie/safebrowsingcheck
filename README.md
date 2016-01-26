# safebrowsingcheck
Splunk app for scanning an url against Googles Safe Browsing API

Info about the Google API: https://developers.google.com/safe-browsing/

The service checks an url and returns either ok, phishing or malware. To test the app you can use the provided csv file.

The splunk query is on the following format:

'index=<index_name> | table <name_of_url_field> | sb field=<name_of_url_field>'

##Example with data from provided csv file:
'index="phishing" | rename "Phish URL" as url | table url | sb field="url"'

This will return a result with the following fields:
- sb_code -> result code from Google SB API (200, 204, 400, 401, 503)
- sb_message -> result message (phishing, malware, unwanted, nothing found)

To use the service you need an API key from Google Developers Console.

Configuration

in sb.conf file add API key and HTTP proxy settings
