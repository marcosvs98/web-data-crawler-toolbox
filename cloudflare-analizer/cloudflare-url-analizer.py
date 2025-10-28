import logging
import re
import sys
from http import HTTPStatus
from urllib.parse import urlparse

import requests

logging.basicConfig(
    level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CloudflareAnalyzer:
    def __init__(self, status_code, response_headers, contents):
        self.status_code = status_code
        self.headers = response_headers
        self.contents = contents

    def is_iuam_challenge(self):
        if self.headers.get('Server', '').startswith('cloudflare') and self.status_code in [
            429,
            503,
        ]:
            try:
                if re.search(
                    r'<form .*?="challenge-form" action="/.*?__cf_chl_jschl_tk__=\S+"',
                    self.contents,
                    re.M | re.S,
                ):
                    return True
            except AttributeError:
                pass
        return False

    def is_new_iuam_challenge(self):
        if self.headers.get('Server', '').startswith('cloudflare') and self.status_code in [
            429,
            503,
        ]:
            try:
                if re.search(
                    r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/orchestrate/jsch/v1"',
                    self.contents,
                    re.M | re.S,
                ) and re.search(r'window._cf_chl_enter\(', self.contents, re.M | re.S):
                    return True
            except AttributeError:
                pass
        return False

    def is_new_captcha_challenge(self):
        if self.is_captcha_challenge():
            try:
                if re.search(
                    r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/orchestrate/captcha/v1"',
                    self.contents,
                    re.M | re.S,
                ) and re.search(r'window._cf_chl_enter\(', self.contents, re.M | re.S):
                    return True
            except AttributeError:
                pass
        return False

    def is_captcha_challenge(self):
        if (
            self.headers.get('Server', '').startswith('cloudflare')
            and self.status_code == HTTPStatus.FORBIDDEN
        ):
            try:
                if re.search(
                    r'action="/\S+__cf_chl_captcha_tk__=\S+', self.contents, re.M | re.DOTALL
                ):
                    return True
            except AttributeError:
                pass
        return False

    def is_firewall_blocked(self):
        if (
            self.headers.get('Server', '').startswith('cloudflare')
            and self.status_code == HTTPStatus.FORBIDDEN
        ):
            try:
                if re.search(
                    r'<span class="cf-error-code">1020</span>', self.contents, re.M | re.DOTALL
                ):
                    return True
            except AttributeError:
                pass
        return False

    def check_challenge_javascript(self):
        try:
            js = re.search(
                r'setTimeout\(function\(\){\s+(.*?a\.value\s*=\s*\S+toFixed\(10\);)',
                self.contents,
                re.M | re.S,
            ).group(1)
            logger.info(js)
        except (IndexError, ValueError, AttributeError):
            pass

    def check_params_extraction(self):
        form_payload = re.search(
            r'<form (?P<form>.*?="challenge-form" '
            r'action="(?P<challengeUUID>.*?'
            r'__cf_chl_jschl_tk__=\S+)"(.*?)</form>)',
            self.contents,
            re.M | re.DOTALL,
        ).groupdict()
        if not all(key in form_payload for key in ['form', 'challengeUUID']):
            return False
        return True

    def is_cloudflare_response(self):
        return 'cloudflare' in self.headers.get('Server', '')


def make_request(url, headers):
    try:
        logger.info(f'Analyzing URL: {url}\n')
        with requests.Session() as session:
            session.max_redirects = 15
            resp = session.get(url, headers=headers, allow_redirects=True, timeout=30)
            logger.info(f'> HTTP/1.1 {resp.status_code} {resp.reason}')
            for k, v in resp.headers.items():
                logger.info(f'> {k}: {v}')
            logger.info('>\n')
            return resp
    except requests.RequestException as e:
        logger.info(f'Request Failed: {e}')
        return None


def main():
    USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'

    url = sys.argv[1]

    headers = {
        'Host': urlparse(url).netloc,
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'TE': 'Trailers',
    }

    resp = make_request(url, headers)

    if resp is None:
        return

    analyzer = CloudflareAnalyzer(resp.status_code, resp.headers, resp.text)

    if not analyzer.is_cloudflare_response():
        logger.info('*** Cloudflare NOT detected!')
        return

    logger.info('*** Cloudflare Headers Detected!')

    if analyzer.is_firewall_blocked():
        logger.info('*** Cloudflare has BLOCKED this request (Code 1020 Detected).')

    if analyzer.is_new_captcha_challenge():
        logger.info('*** Cloudflare version 2 CAPTCHA Detected. [pheew!]')

    if analyzer.is_new_iuam_challenge():
        logger.info('*** Cloudflare Version 2 CHALLENGE Detected. [pheew!]')

    if analyzer.is_captcha_challenge():
        logger.info('*** Cloudflare Version 1 CAPTCHA Detected. [pheew!]')

    if analyzer.is_iuam_challenge():
        logger.info('*** Cloudflare Version 1 CHALLENGE Detected. [hooray!]')

        if not analyzer.check_challenge_javascript():
            logger.info('\t*** Unable to identify Cloudflare IUAM Javascript on website. [pheew!]')

        if not analyzer.check_params_extraction():
            logger.info('\t*** Unable to extract parameters. [pheew!]')


if __name__ == '__main__':
    main()
