import io
import sys
import pycurl
import certifi
import logging
import socket
from urllib.parse import urlencode, urlparse
from http.client import responses as reasons
from dataclasses import dataclass, field

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


@dataclass
class HTTPRedirectHistoryItem():
    http_version: str = None
    status_code: int = 0
    reason: str = None
    headers: list = None

    def __setattr__(self, name, value):
        if name == 'status_code':
            self.__dict__['reason'] = reasons.get(value)
        self.__dict__[name] = value


@dataclass
class HTTPRequest():
    url: str
    method: str
    domain: str = field(default=None)
    scheme: str = field(default=None)
    headers: list = field(default=None)
    postdata: bytes = field(default=None, repr=False)
    http_version: str = field(default='HTTP/1.1')
    timeout: int = field(default=120)
    follow_redirects: bool = field(default=True)
    max_redirects: int = field(default=30)
    proxy_host: str = field(default=None)
    proxy_port: int = field(default=0)
    proxy_username: str = field(default=None)
    proxy_password: str = field(default=None)
    outbound_address: str = field(default=None)
    ssl_verify: bool = field(default=False)

    def __post_init__(self):
        uri = urlparse(self.url)
        self.domain = uri.netloc
        self.scheme = uri.scheme

    def __setattr__(self, name, value):
        if name == 'url':
            uri = urlparse(value)
            self.__dict__['domain'] = uri.netloc
            self.__dict__['scheme'] = uri.scheme
        self.__dict__[name] = value


@dataclass
class HTTPResponse():
    """Class representing the fields of an HTTP response."""
    status_code: int
    http_version: str = field(default='HTTP/1.1')
    reason: str = field(default=None)
    headers: list = field(default=None)
    content_length: int = field(default=0)
    content_type: str = field(default=None)
    contents: bytes = field(default=None, repr=False)
    text: str = field(default=None, repr=False)
    detected_encoding: str = field(default=None)
    time_elapsed: int = field(default=0)
    url_final: str = field(default=None)
    redirect_count: int = field(default=0)
    history: list = field(default=None)
    remote_address: str = field(default=None)
    outbound_address: str = field(default=None)
    request: HTTPRequest = field(default=None)

    def __post_init__(self):
        self.reason = reasons.get(self.status_code)

    def __setattr__(self, name, value):
        if name == 'status_code':
            self.__dict__['reason'] = reasons.get(value)
        self.__dict__[name] = value


class HTTPClient():
    """Class responsible for making HTTP requests using pycurl."""
    def __init__(self):
        self.curl = pycurl.Curl()
        self.response_history = None
        self.contents_buffer = None

    def _debug_callback(self, cod, msg, stream):
        infotype = ['TEXT', 'HEADER_IN', 'HEADER_OUT', 'DATA_IN',
                    'DATA_OUT', 'SSL_DATA_IN','SSL_DATA_OUT', 'END']
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
                http_version=version, status_code=int(status),
                headers=[])
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
            if((laddr is not None) and (family == socket.AF_INET)):
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
        self.curl.setopt(pycurl.DEBUGFUNCTION,
                         lambda cod, msg: self._debug_callback(cod, msg, debug_stream))
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
            logger.debug(f'Proxy Server Enabled: address="{request.proxy_host}" port="{request.proxy_port}"')
            self.curl.setopt(pycurl.PROXY, f'{request.proxy_host}:{request.proxy_port}')

            # HTTP Proxy Authentication
            if request.proxy_username:
                logger.debug(f'Proxy Server Authentication Enabled: username="{request.proxy_username}" '
                          f'password="{request.proxy_password}"')
                self.curl.setopt(pycurl.PROXYUSERPWD, f'{request.proxy_username}:{request.proxy_password}')

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
        self.curl.setopt(pycurl.OPENSOCKETFUNCTION,
                         lambda purpose, address: self._open_socket_callback((purpose,) + address + (local_address,)))

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
            elif 'from proxy' in msg and 'CONNECT' in msg:
                raise HTTPClientProxyException(msg)
            else:
                raise HTTPClientException(msg)

        try:
            content_type = self.curl.getinfo(pycurl.CONTENT_TYPE)
        except TypeError:
            content_type = None

        try:
            contents_buffer = self.contents_buffer.getvalue()
            detected_encoding, contents_text = self._auto_decode(contents_buffer)
        except TypeError:
            contents_buffer = None
            contents_text = None
            detected_encoding = None

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
            outbound_address=self.curl.getinfo(pycurl.LOCAL_IP))

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