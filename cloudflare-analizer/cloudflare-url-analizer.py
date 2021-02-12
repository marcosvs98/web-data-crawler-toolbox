################################################################################
##           __          __  _      _____ _       _           _               ##
##           \ \        / / | |    / ____| |     | |         | |              ##
##            \ \  /\  / /__| |__ | |  __| | ___ | |__   __ _| |              ##
##             \ \/  \/ / _ \ '_ \| | |_ | |/ _ \| '_ \ / _` | |              ##
##              \  /\  /  __/ |_) | |__| | | (_) | |_) | (_| | |              ##
##               \/  \/ \___|_.__/ \_____|_|\___/|_.__/ \__,_|_|              ##
##                                                                            ##
##        Copyright (c) 2020 WebGlobal - Todos os Direitos Reservados         ##
##                                                                            ##
################################################################################
import re
import sys
import requests
from urllib.parse import urlparse

class CloudflareAnalizer():
	def __init__(self, status_code, response_headers, contents):
		self.status_code = status_code
		self.headers = response_headers
		self.contents = contents

	def is_IUAM_challenge(self):
		"""
			https://github.com/VeNoMouS/cloudscraper/blob/133166ebc195b6f9b60db06d56829dbf6bd574c4/cloudscraper/__init__.py#L310
		"""
		if (self.headers.get('Server', '').startswith('cloudflare') and self.status_code in [429, 503]):
			try:
				if re.search(r'<form .*?="challenge-form" action="/.*?__cf_chl_jschl_tk__=\S+"', self.contents, re.M | re.S):
					return True
			except AttributeError:
				pass
		return False

	def is_new_IUAM_challenge(self):
		"""
			https://github.com/VeNoMouS/cloudscraper/blob/133166ebc195b6f9b60db06d56829dbf6bd574c4/cloudscraper/__init__.py#L331
		"""
		if (self.headers.get('Server', '').startswith('cloudflare') and self.status_code in [429, 503]):
			try:
				if(re.search(r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/orchestrate/jsch/v1"', self.contents, re.M | re.S) and
					re.search(r'window._cf_chl_enter\(', self.contents, re.M | re.S)):
					return True
			except AttributeError:
				pass
		return False

	def is_new_captcha_challenge(self):
		"""
			https://github.com/VeNoMouS/cloudscraper/blob/133166ebc195b6f9b60db06d56829dbf6bd574c4/cloudscraper/__init__.py#L353
		"""
		if self.is_captcha_challenge():
			try:
				if(re.search(r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/orchestrate/captcha/v1"', self.contents, re.M | re.S) and
					re.search(r'window._cf_chl_enter\(', self.contents, re.M | re.S)):
					return True
			except AttributeError:
				pass
		return False

	def is_captcha_challenge(self):
		"""
			https://github.com/VeNoMouS/cloudscraper/blob/133166ebc195b6f9b60db06d56829dbf6bd574c4/cloudscraper/__init__.py#L374
		"""
		if(self.headers.get('Server', '').startswith('cloudflare') and self.status_code == 403):
			try:
				if re.search(r'action="/\S+__cf_chl_captcha_tk__=\S+', self.contents, re.M | re.DOTALL):
					return True
			except AttributeError:
				pass
		return False

	def is_firewall_blocked(self):
		"""
			https://github.com/VeNoMouS/cloudscraper/blob/133166ebc195b6f9b60db06d56829dbf6bd574c4/cloudscraper/__init__.py#L395
		"""
		if(self.headers.get('Server', '').startswith('cloudflare') and self.status_code == 403):
			try:
				if re.search(r'<span class="cf-error-code">1020</span>', self.contents, re.M | re.DOTALL):
					return True
			except AttributeError:
				pass
		return False

	def check_challenge_javascript(self):
		#try:
		js = re.search(r'setTimeout\(function\(\){\s+(.*?a\.value\s*=\s*\S+toFixed\(10\);)',
			self.contents, re.M | re.S).group(1)
		print(js)
		#return True
		#except (IndexError, ValueError, AttributeError):
		#	return False

	def check_params_extration(self):
		formPayload = re.search(
			r'<form (?P<form>.*?="challenge-form" '
			r'action="(?P<challengeUUID>.*?'
			r'__cf_chl_jschl_tk__=\S+)"(.*?)</form>)',
			self.contents, re.M | re.DOTALL).groupdict()
		if not all(key in formPayload for key in ['form', 'challengeUUID']):
			return False
		return True

	def is_cloudflare_response(self):
		return 'cloudflare' in self.headers.get('Server', '')

def main():
	url = sys.argv[1]

	headers = {
		'Host': urlparse(url).netloc,
		'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate, br',
		'Connection': 'keep-alive',
		'Upgrade-Insecure-Requests': '1',
		'Pragma': 'no-cache',
		'Cache-Control': 'no-cache',
		'TE': 'Trailers'
	}

	try:
		print(f'Analizing URL: {url}\n')
		session = requests.Session()
		session.max_redirects = 15
		resp = session.get(url, headers=headers,
			allow_redirects=True, timeout=30)
		print(f'> HTTP/1.1 {resp.status_code} {resp.reason}')
		for k, v in resp.headers.items():
			print(f'> {k}: {v}')
		print('>\n')
	except requests.RequestException as e:
		print(f'Request Failed: {e}')
		return

	analizer = CloudflareAnalizer(resp.status_code, resp.headers, resp.text)

	if not analizer.is_cloudflare_response():
		print('*** Cloudflare NOT detected!')
		return

	print('*** Cloudflare Headers Detected!')

	if analizer.is_firewall_blocked():
		print('*** Cloudflare has BLOCKED this request (Code 1020 Detected).')

	if analizer.is_new_captcha_challenge():
		print('*** Cloudflare version 2 CAPTCHA Detected. [pheew!]')

	if analizer.is_new_IUAM_challenge():
		print('*** Cloudflare Version 2 CHALLENGE Detected. [pheew!]')

	if analizer.is_captcha_challenge():
		print('*** Cloudflare Version 1 CAPTCHA Detected. [pheew!]')

	if analizer.is_IUAM_challenge():
		print('*** Cloudflare Version 1 CHALLENGE Detected. [hooray!]')

		if not analizer.check_challenge_javascript():
			print('\t*** Unable to identify Cloudflare IUAM Javascript on website. [pheew!]')

		if not analizer.check_params_extration():
			print('\t*** Unable to extract parameters. [pheew!]')

if __name__ == '__main__':
	main()

# fim-de-arquivo #

