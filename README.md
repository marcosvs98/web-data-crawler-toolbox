# Web Data Crawler Toolbox

This repository hosts a collection of Python tools specifically tailored for web data crawling, subdomain discovery, and related tasks. Each utility is designed with a specific function to streamline web-related operations efficiently.

## Included Tools:

1. **Domain Scanner:** Scans and discovers subdomains associated with a given domain using DNS resolution.

2. **Public Proxies:** Retrieves and parses free, public proxy lists, allowing for filtering based on criteria like country and anonymity level.

3. **HTTP Client with cURL:** Employs `pycurl` to create a versatile HTTP client for making requests to web servers, supporting various HTTP methods, redirects, timeouts, proxy configurations, and SSL verification control.

4. **Cloudflare Analyzer:** Analyzes and identifies if a website is protected by the Cloudflare security service.

5. **DNS Scanner:** Performs scanning and enumeration of DNS records for a given domain using the `dns.resolver` module.

## Installation:

Clone the repository to integrate these utilities into your Python project.

```bash
git clone https://github.com/your-username/python-web-data-crawler.git 
```

## Dependencies:

Ensure the following dependencies are installed:

- [pycurl](http://pycurl.io/)
- [certifi](https://pypi.org/project/certifi/)

Install dependencies using:

```bash
pip install pycurl certifi
```
