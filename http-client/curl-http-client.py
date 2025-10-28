import io
import logging
import socket
import sys
from http.client import responses as reasons
from urllib.parse import urlencode, urlparse

import certifi
import pycurl

logging.basicConfig(
    level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('HTTPClient')


class HTTPClientException(Exception):
    """Base exception class for HTTPClient."""


class HTTPClientEmptyResponseException(HTTPClientException):
    """Exception raised when the server response is empty."""


class HTTPClientTimeoutException(HTTPClientException):
    """Exception raised when the HTTP request times out."""


class HTTPClientTooManyRedirectsException(HTTPClientException):
    """Exception raised when there are too many redirects during the HTTP request."""


class HTTPClientResolveHostException(HTTPClientException):
    """Exception raised when the host resolution fails during the HTTP request."""


class HTTPClientProxyException(HTTPClientException):
    """Base exception class for HTTP proxy-related exceptions."""


class HTTPClientResolveProxyHostException(HTTPClientProxyException):
    """Exception raised when the resolution of the proxy host fails during the HTTP request."""


class HTTPRedirectHistoryItem:
    def __init__(self, http_version=None, status_code=0, reason=None, headers=None):
        self.http_version = http_version
        self.status_code = status_code
        self.reason = reason
        self.headers = headers if headers is not None else []
        if status_code != 0:
            self.reason = reasons.get(status_code)


class HTTPRequest:
    def __init__(
        self,
        url,
        method,
        domain=None,
        scheme=None,
        headers=None,
        postdata=None,
        http_version='HTTP/1.1',
        timeout=120,
        follow_redirects=True,
        max_redirects=30,
        proxy_host=None,
        proxy_port=0,
        proxy_username=None,
        proxy_password=None,
        outbound_address=None,
        ssl_verify=False,
    ):
        self.url = url
        self.method = method
        self.headers = headers
        self.postdata = postdata
        self.http_version = http_version
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.outbound_address = outbound_address
        self.ssl_verify = ssl_verify

        uri = urlparse(url)
        self.domain = domain if domain is not None else uri.netloc
        self.scheme = scheme if scheme is not None else uri.scheme

    def __repr__(self):
        return (
            f"HTTPRequest(url='{self.url}', method='{self.method}', "
            f"domain='{self.domain}', scheme='{self.scheme}')"
        )


class HTTPResponse:
    """Class representing the fields of an HTTP response."""

    def __init__(
        self,
        request=None,
        http_version='HTTP/1.1',
        reason=None,
        headers=None,
        content_length=0,
        content_type=None,
        contents=None,
        text=None,
        detected_encoding=None,
        time_elapsed=0,
        url_final=None,
        redirect_count=0,
        history=None,
        remote_address=None,
        outbound_address=None,
        status_code=0,
    ):
        self.status_code = status_code
        self.http_version = http_version
        self.reason = (
            reason if reason is not None else reasons.get(status_code) if status_code else None
        )
        self.headers = headers
        self.content_length = content_length
        self.content_type = content_type
        self.contents = contents
        self.text = text
        self.detected_encoding = detected_encoding
        self.time_elapsed = time_elapsed
        self.url_final = url_final
        self.redirect_count = redirect_count
        self.history = history
        self.remote_address = remote_address
        self.outbound_address = outbound_address
        self.request = request

    def __repr__(self):
        return (
            f"HTTPResponse(status_code={self.status_code}, "
            f"http_version='{self.http_version}', reason='{self.reason}')"
        )


class HTTPClient:
    """Class responsible for making HTTP requests using pycurl."""

    def __init__(self):
        self.curl = pycurl.Curl()
        self.response_history = None
        self.contents_buffer = None

    def _debug_callback(self, cod, msg, stream):
        infotype = [
            'TEXT',
            'HEADER_IN',
            'HEADER_OUT',
            'DATA_IN',
            'DATA_OUT',
            'SSL_DATA_IN',
            'SSL_DATA_OUT',
            'END',
        ]
        typename = infotype[cod]
        if cod in (0, 1, 2):
            for line in msg.decode().splitlines():
                if stream:
                    print(f'[{typename}] {line}', file=stream)
                    logger.debug(f'[{typename}] {line}')
        elif cod in (3, 4, 5, 6):
            if stream:
                print(f'[{typename}] size={len(msg)}', file=stream)
                logger.debug(f'[{typename}] size={len(msg)}')

    def _response_header_callback(self, rawheader):
        raw = rawheader.decode('latin1')
        if not self.response_history:
            self.response_history = [None]
        if not self.response_history[0]:
            version, status, _ = raw.strip().split(maxsplit=2)
            self.response_history[0] = HTTPRedirectHistoryItem(
                http_version=version, status_code=int(status), headers=[]
            )
        elif ':' in raw:
            name, value = raw.split(':', 1)
            name, value = name.strip(), value.strip()
            self.response_history[0].headers.append((name, value))
        elif (raw == '\r\n') or (raw == '\n'):
            self.response_history.insert(0, None)

    def _open_socket_callback(self, args):
        purpose, family, socktype, proto, raddr, laddr = args
        s = socket.socket(family, socktype, proto)
        try:
            if (laddr is not None) and (family == socket.AF_INET):
                s.bind(laddr)
        except OSError as e:
            logger.debug(f"Cannot bind local address '{laddr}' to socket '{s}': {e}")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        logger.debug(f'Open Socket: {s}')
        return s

    def _auto_decode(self, contents):
        for enc in ['ascii', 'utf8', 'iso-8859-1', 'cp-1252']:
            try:
                return (enc, contents.decode(enc))
            except UnicodeDecodeError:
                pass
        return ('ascii', contents.decode('ascii', errors='ignore'))

    def send_request(self, request=None, debug_enabled=False, debug_stream=sys.stdout, **kwargs):
        if request is None:
            request = HTTPRequest(**kwargs)

        logger.debug(f'HTTP Client Request: {request}')

        # URL
        self.curl.setopt(pycurl.URL, request.url)

        # Timeout
        self.curl.setopt(pycurl.TIMEOUT, request.timeout)

        # Redirects
        self.curl.setopt(pycurl.FOLLOWLOCATION, request.follow_redirects)
        self.curl.setopt(pycurl.MAXREDIRS, request.max_redirects)

        # Debug Callback / Verbose
        self.curl.setopt(
            pycurl.DEBUGFUNCTION, lambda cod, msg: self._debug_callback(cod, msg, debug_stream)
        )
        self.curl.setopt(pycurl.VERBOSE, debug_enabled)

        # Certificates / SSL
        self.curl.setopt(pycurl.SSL_VERIFYPEER, request.ssl_verify)
        self.curl.setopt(pycurl.SSL_VERIFYHOST, request.ssl_verify)
        self.curl.setopt(pycurl.CAINFO, certifi.where() if request.ssl_verify else None)

        # HTTP Protocol Version
        self.curl.setopt(pycurl.HTTP_VERSION, getattr(pycurl, f'CURL_{request.http_version}'))

        # HTTP Method
        if request.method in ['GET', 'POST', 'HEAD']:
            self.curl.setopt(getattr(pycurl, request.method), True)
            if request.method == 'POST' and request.postdata:
                self.curl.setopt(pycurl.POSTFIELDS, urlencode(request.postdata))
        else:
            raise HTTPClientException(f'Unsupported HTTP Method: "{request.method}"')

        # HTTP Proxy
        if request.proxy_host:
            logger.debug(
                f'Proxy Server Enabled: address="{request.proxy_host}" port="{request.proxy_port}"'
            )
            self.curl.setopt(pycurl.PROXY, f'{request.proxy_host}:{request.proxy_port}')

            # HTTP Proxy Authentication
            if request.proxy_username:
                logger.debug(
                    f'Proxy Server Authentication Enabled: username="{request.proxy_username}" '
                    f'password="{request.proxy_password}"'
                )
                self.curl.setopt(
                    pycurl.PROXYUSERPWD, f'{request.proxy_username}:{request.proxy_password}'
                )

        # Request Headers
        if request.headers is not None:
            if not isinstance(request.headers, (list, tuple)):
                raise HTTPClientException(f'Invalid request headers')
            if not all(isinstance(i, (tuple, list)) for i in request.headers):
                raise HTTPClientException(f'Invalid request headers')
            if not all(len(i) == 2 for i in request.headers):
                raise HTTPClientException(f'Invalid request headers')
            rawheaders = [f'{k}: {v}' for k, v in request.headers]
            self.curl.setopt(pycurl.HTTPHEADER, rawheaders)

        # Write Contents Callback
        self.contents_buffer = io.BytesIO()
        self.curl.setopt(pycurl.WRITEFUNCTION, self.contents_buffer.write)

        # Response Headers Callback
        self.response_history = None
        self.curl.setopt(pycurl.HEADERFUNCTION, self._response_header_callback)

        # Local Address
        local_address = ('0.0.0.0', 0)
        if request.outbound_address:
            local_address = (request.outbound_address, 0)

        # Open Socket Callback
        self.curl.setopt(
            pycurl.OPENSOCKETFUNCTION,
            lambda purpose, address: self._open_socket_callback(
                (purpose,) + address + (local_address,)
            ),
        )

        # Socket: Force disconnection after completing the interaction, Not reuse
        self.curl.setopt(pycurl.FORBID_REUSE, True)

        # Socket: Force new connection, Replace the connection in the cache
        self.curl.setopt(pycurl.FRESH_CONNECT, True)

        # Perform!
        try:
            self.curl.perform()
            if self.curl.getinfo(pycurl.HTTP_CODE) == 0:
                raise HTTPClientEmptyResponseException('Empty Server Response')
        except pycurl.error as e:
            cod, msg = e.args
            if cod in [pycurl.E_OPERATION_TIMEDOUT, pycurl.E_OPERATION_TIMEOUTED]:
                raise HTTPClientTimeoutException(msg)
            elif cod == pycurl.E_TOO_MANY_REDIRECTS:
                raise HTTPClientTooManyRedirectsException(msg)
            elif cod == pycurl.E_COULDNT_RESOLVE_HOST:
                raise HTTPClientResolveHostException(msg)
            elif cod == pycurl.E_COULDNT_RESOLVE_PROXY:
                raise HTTPClientResolveProxyHostException(msg)
            elif isinstance(msg, str) and 'from proxy' in msg and 'CONNECT' in msg:
                raise HTTPClientProxyException(msg)
            else:
                raise HTTPClientException(msg)

        try:
            content_type = self.curl.getinfo(pycurl.CONTENT_TYPE)
        except (TypeError, AttributeError):
            content_type = None

        try:
            contents_buffer = self.contents_buffer.getvalue()
            detected_encoding, contents_text = self._auto_decode(contents_buffer)
        except (TypeError, AttributeError):
            contents_buffer = None
            contents_text = None
            detected_encoding = None

        # Ensure response_history is properly initialized
        if not self.response_history or len(self.response_history) < 2:
            raise HTTPClientEmptyResponseException('Invalid response history')

        response = HTTPResponse(
            request=request,
            http_version=self.response_history[1].http_version,
            status_code=self.response_history[1].status_code,
            headers=self.response_history[1].headers,
            content_type=content_type,
            content_length=self.contents_buffer.getbuffer().nbytes,
            contents=contents_buffer,
            text=contents_text,
            detected_encoding=detected_encoding,
            time_elapsed=self.curl.getinfo(pycurl.TOTAL_TIME),
            url_final=self.curl.getinfo(pycurl.EFFECTIVE_URL),
            redirect_count=self.curl.getinfo(pycurl.REDIRECT_COUNT),
            history=self.response_history[1:],
            remote_address=self.curl.getinfo(pycurl.PRIMARY_IP),
            outbound_address=self.curl.getinfo(pycurl.LOCAL_IP),
        )

        logger.debug(f'HTTP Server Response: {response}')
        return response

    def get(self, url, **kwargs):
        kwargs.update({'url': url, 'method': 'GET'})
        return self.send_request(**kwargs)

    def post(self, url, **kwargs):
        kwargs.update({'url': url, 'method': 'POST'})
        return self.send_request(**kwargs)

    def head(self, url, **kwargs):
        kwargs.update({'url': url, 'method': 'HEAD'})
        return self.send_request(**kwargs)

    def __del__(self):
        self.curl.close()
