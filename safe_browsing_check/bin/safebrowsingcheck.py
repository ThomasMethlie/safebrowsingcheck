#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
import logging.handlers
import os
import sys
import urllib2

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from ConfigParser import SafeConfigParser

@Configuration()
class SafeBrowsingCheckCommand(StreamingCommand):
    """Google Safe Browsing Check

     | sb field=<field>
    """

    field = Option(name='field', doc=None, require=True)
    suppress_error = Option(name='suppress_error', doc=None, require=False, default=False,
                            validate=validators.Boolean())
    enable_proxy = False
    http_proxy = None
    https_proxy = None
    api_key = None
    app_version = None
    protocol_version = None
    client = None

    def stream(self, events):
        self.get_config()
        logger = logging.getLogger('SafeBrowsingCheckCommand')

        for event in events:
            if not self.field in event:
                continue

            try:
                logger.info(event[self.field])
                code, message = self.get_safe_browsing_result(event[self.field].strip())

                event["sb_code"] = code
                event["sb_message"] = message

            except Exception, e:
                logger.error(e.message)
                if not self.suppress_error:
                    raise e

            yield event

    def get_safe_browsing_result(self, arg_query_data):
        logger = logging.getLogger('SafeBrowsingCheckCommand')

        if self.enable_proxy is True:
            proxy = urllib2.ProxyHandler({'http': self.http_proxy, 'https': self.https_proxy})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)

        headers = {"Connection": "keep-alive", "Cache-Control": "max-age=0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                   "Origin": "",
                   "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.89 Safari/537.36",
                   "Content-Type": "application/x-www-form-urlencoded",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US;q=0.6,en;q=0.4"}
        request = urllib2.Request(
                "https://sb-ssl.google.com/safebrowsing/api/lookup?client=" + self.client + "&key=" + self.api_key + "&appver=" + self.app_version + "&pver=" + self.protocol_version + "&url=" + arg_query_data)

        logger.warning(request.get_full_url())
        for key in headers:
            request.add_header(key, headers[key])

        """
        200: The queried URL is either phishing, malware, or both; see the response body for the specific type.
        204: The requested URL is legitimate and no response body is returned.
        400: Bad Request—The HTTP request was not correctly formed.
        401: Not Authorized—The API key is not authorized.
        503: Service Unavailable—The server cannot handle the request. Besides the normal server failures, this can also indicate that the client has been “throttled” for sending too many requests.
        """
        try:
            response_data = "-"
            response_code = "-"
            response = urllib2.urlopen(request, timeout=3)

            if response.getcode() == 200:
                """Look in response body to determine if its phising, malware or both"""
                response_code = 200
                response_data = response.read()
            elif response.getcode() == 204:
                response_code = 204
                response_data = "The requested URL is legitimate."
            elif response.getcode() == 400:
                response_code = 400
                response_data = "Bad Request—The HTTP request was not correctly formed."
            elif response.getcode() == 401:
                response_code = 401
                response_data = "Not Authorized—The API key is not authorized"
            elif response.getcode() == 503:
                response_code = 503
                response_data = "Service Unavailable"
            else:
                response_data = "Unable to get response!"

            response.close()
        except urllib2.URLError, e:
            logger.warning("Socket timeout... Please check your internet connection.")
            logger.warning(e.message)
            response_data = "There was a problem connecting to Google Safe Browsing API"

        return response_code, response_data

    def get_config(self):
        logger = logging.getLogger('SafeBrowsingCheckCommand')
        try:
            path = os.path.join(os.environ['SPLUNK_HOME'], 'etc/apps/safe_browsing_check/local/sb.conf')

            config = SafeConfigParser()
            config.read(path)

            if config.has_section('settings'):
                if config.has_option('settings', 'is_use_proxy'):
                    self.enable_proxy = config.getboolean('settings', 'is_use_proxy')

                if config.has_option('settings', 'http_proxy'):
                    self.http_proxy = config.get('settings', 'http_proxy').strip('""')

                if config.has_option('settings', 'https_proxy'):
                    self.https_proxy = config.get('settings', 'https_proxy').strip('""')

                if config.has_option('settings', 'api_key'):
                    self.api_key = config.get('settings', 'api_key').strip('""')

                if config.has_option('settings', 'client'):
                    self.client = config.get('settings', 'client').strip('""')

                if config.has_option('settings', 'app_version'):
                    self.app_version = config.get('settings', 'app_version').strip('""')

                if config.has_option('settings', 'protocol_version'):
                    self.protocol_version = config.get('settings', 'protocol_version').strip('""')

                if self.http_proxy is None and self.https_proxy is None:
                    self.enable_proxy = False
        except Exception, e:
            logger.warning('error in parsing config', e.message)
            raise e

dispatch(SafeBrowsingCheckCommand, sys.argv, sys.stdin, sys.stdout, __name__)
