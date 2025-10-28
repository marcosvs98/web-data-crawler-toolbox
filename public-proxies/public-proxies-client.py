import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.request import urlopen

logging.basicConfig(
    level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger('proxy-list')

PUBLIC_PROXIES_RAW = (
    'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt'
)
PUBLIC_PROXIES_LIST = 'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt'
PUBLIC_PROXIES_STATUS = (
    'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-status.txt'
)


class InvalidProxyToParser(Exception):
    pass


@dataclass(repr=True)
class ProxyParsed:
    proxy_host: str
    proxy_port: int
    proxy_scheme: str
    proxy_level_anonymity: int
    proxy_country: str
    proxy_google_passed: bool
    proxy_outgoing_ip: bool
    proxy_uri: str
    proxy_user: str = field(default=None)
    proxy_pass: str = field(default=None)
    proxy_status: str = field(default='no-status-available')

    def __repr__(self):
        return f'ProxyParsed(uri={self.proxy_uri})'


class ProxyListClient:
    """
    A list of free, public and forward proxy servers.
    Available daily on 'https://github.com/clarketm/proxy-list'.

    # Definitions
        ----------------------------------------------------------------
        1. IP address
        2. Port number
        3. Country code
        4. Anonymity
           N = No anonymity
           A = Anonymity
           H = High anonymity
        5. Type
             = HTTP
           S = HTTP/HTTPS
           ! = incoming IP different from outgoing IP
        6. Google passed
           + = Yes
           – = No
        ----------------------------------------------------------------
    """

    def __init__(self, proxies=None, outfile='proxy-list-cache.json', tolerance=10):
        self._proxies_result = {}
        self._proxies_status = {}
        self._proxies = proxies
        self._outfile = outfile
        self._tolerance = tolerance
        self._running = False
        self._update_proxies()
        self._info = self.get_proxy_info

    def _initialize(self):
        self._update_proxies()
        self._nthreads = round(self._info.num_proxies / 2)
        self._threads = [None] * self._nthreads
        self._running = False

        if not self._running:
            self._running = True
            for i in range(self._nthreads):
                self._threads[i] = threading.Thread(target=self._thread_handler)
                self._threads[i].daemon = True
                self._threads[i].start()
                self._nthreads = 0

    def get_proxies(self, proxy_path=None, limit=-1):
        try:
            with open(self._outfile) as f:
                proxies = json.load(f)
                if proxy_path:
                    try:
                        path_parts = proxy_path.split('.')
                        if len(path_parts) != 2:
                            raise ValueError('Invalid proxy_path format')
                        p, s = path_parts
                        proxy_list = proxies.get(p, {}).get(s, [])
                        if limit > 0:
                            proxy_list = proxy_list[:limit]
                        return [ProxyParsed(**proxy) for proxy in proxy_list]
                    except (KeyError, ValueError) as e:
                        raise KeyError('this filter is not available') from e
                return proxies.get('raw', [])
        except FileNotFoundError:
            log.error(f'Proxy list file not found: {self._outfile}')
            return []

    def _thread_handler(self):
        try:
            self.before_handler()
            self._update_proxies()
            self.after_handler()
        except Exception as e:
            log.error(f'Error in thread handler: {e}')

    def _get_proxy_list_status(self):
        try:
            response = urlopen(PUBLIC_PROXIES_STATUS, timeout=30)
            content_text = response.read().decode('utf-8')
            proxies_status = content_text.split('\n')
            for proxy in proxies_status:
                try:
                    address, status = proxy.split(': ', 1)
                    self._proxies_status[address] = status
                except ValueError:
                    continue
        except Exception as e:
            log.error(f'Error fetching proxy status: {e}')

    def _order_proxies_by(self, proxy_item, ref, name=None):
        if name not in self._proxies_result:
            self._proxies_result[name] = {}
        if ref not in self._proxies_result[name]:
            self._proxies_result[name][ref] = []
        self._proxies_result[name][ref].append(proxy_item.__dict__)

    def _updated_proxies(self):
        with open(self._outfile) as f:
            try:
                cache = json.load(f)
                string_date = (
                    cache['info']['header'][0]
                    .split(',')[-1]
                    .partition(',')[0]
                    .partition(' +')[0]
                    .strip()
                )
                inserted = datetime.strptime(string_date, '%d %b %y %H:%M:%S')
                updated = datetime.strptime(cache['info']['updated'], '%Y-%m-%d %H:%M:%S.%f')
                tolerance = inserted + timedelta(hours=self._tolerance)
                if tolerance < updated:
                    return True
            except (KeyError, AttributeError):
                pass

    def _update_proxies(self):
        try:
            if self._updated_proxies():
                return
        except FileNotFoundError:
            pass
        self._get_proxy_list_status()
        try:
            response = urlopen(PUBLIC_PROXIES_LIST, timeout=30)
            content_text = response.read().decode('utf-8')
            proxies = content_text.split('\n\n')
            proxies_header = proxies[0]
            proxies_list = proxies[1].split('\n')
            self._proxies_result['info'] = {}
            for proxy_line in proxies_list:
                if not proxy_line.strip():
                    continue
                proxy_item = self._parse(proxy_line)
                try:
                    # get proxies status
                    proxy_item.proxy_status = self._proxies_status[proxy_item.proxy_host]
                except KeyError:
                    pass
                # sort by proxy status
                self._order_proxies_by(proxy_item, ref=proxy_item.proxy_status, name='status')
                # sort by schema type
                self._order_proxies_by(proxy_item, ref=proxy_item.proxy_scheme, name='scheme')
                # sort by anonymity level
                self._order_proxies_by(
                    proxy_item, ref=proxy_item.proxy_level_anonymity, name='level_anonymity'
                )
                # sort by country of origin
                self._order_proxies_by(proxy_item, ref=proxy_item.proxy_country, name='country')
                # sorts by http port
                self._order_proxies_by(proxy_item, ref=proxy_item.proxy_port, name='http-port')
                # sort by proxy who goes through google
                self._order_proxies_by(
                    proxy_item, ref=proxy_item.proxy_google_passed, name='google_passed'
                )
                # all proxies
                if 'raw' not in self._proxies_result:
                    self._proxies_result['raw'] = []
                self._proxies_result['raw'].append(proxy_item.__dict__)
            # parsing headers info
            self._proxies_result['info']['header'] = [line for line in proxies_header.split('\n')]
            self._proxies_result['info']['updated'] = str(datetime.now())
            self._proxies_result['info']['num_proxies'] = len(proxies_list)
            # statistics
            self._proxies_result['info']['success'] = len(
                self._proxies_result.get('status', {}).get('success', [])
            )
            self._proxies_result['info']['failure'] = len(
                self._proxies_result.get('status', {}).get('failure', [])
            )
            self._proxies_result['info']['no-status-available'] = len(
                self._proxies_result.get('status', {}).get('no-status-available', [])
            )
            success_rate = (
                round(
                    100
                    * (sum(1 for s in self._proxies_status.values() if s == 'success'))
                    / len(self._proxies_status),
                    2,
                )
                if self._proxies_status
                else 0
            )
            self._proxies_result['info']['success_rate'] = f"{success_rate}%"
            self._proxies_result['info']['failure_rate'] = f"{100.00 - success_rate}%"
            # Prepare a json file for cache
            with open(self._outfile, 'w') as f:
                json.dump(self._proxies_result, f, indent=4)
            log.warning(
                f"success_rate={self._proxies_result['info']['success_rate']} "
                f"failure_rate={self._proxies_result['info']['failure_rate']} "
            )
        except Exception as e:
            log.error(f'Error updating proxies: {e}')
            raise

    def _parse(self, proxy_line):
        """
        IP [1]
        |
        | Port [2]
        |   |
        |   | Country [3]
        |   |   |
        |   |   | Anonymity [4]
        |   |   |  |
        |   |   |  |  Type [5]
        |   |   |  |   |_ _ _ _
        |   |   |  |_ _ _ _ _  | Google passed [6]
        |   |   |_ _ _ _ _   | |  |
        |   |_ _ _ _ _    |  | |  |
        |             |   |  | |  |
        200.2.125.90:8080 AR-N-S! +
        └────────────┬────────────┘
                 Proxy line
        """
        try:
            proxy_splited = proxy_line.split(' ')
            proxy_address_info = proxy_splited[0].split(':')
            proxy_host = proxy_address_info[0]
            proxy_port = proxy_address_info[1]
            proxy_info = proxy_splited[1].split('-')
            proxy_country = proxy_info[0]
            proxy_level_anonymity = self._parse_anonymity(proxy_info[1])
            proxy_type = self._parse_proxy_type(proxy_info)
            proxy_outgoing_ip = self._parse_output_ip(proxy_type)
            proxy_scheme = self._parse_http_type(proxy_type)
            proxy_google_passed = self._parse_google_passed(proxy_line)
            proxy_uri = f"{proxy_scheme}://{proxy_host}:{proxy_port}/"

            proxy_parsed = ProxyParsed(
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                proxy_scheme=proxy_scheme,
                proxy_level_anonymity=proxy_level_anonymity,
                proxy_country=proxy_country,
                proxy_google_passed=proxy_google_passed,
                proxy_outgoing_ip=proxy_outgoing_ip,
                proxy_uri=proxy_uri,
            )
            return proxy_parsed
        except IndexError as e:
            raise InvalidProxyToParser(e)

    @property
    def get_proxy_info(self):
        try:
            with open(self._outfile) as f:
                cache = json.load(f)
                return SimpleNamespace(**cache['info'])
        except (KeyError, AttributeError, FileNotFoundError) as e:
            raise ValueError('Unable to get information from the proxy list') from e

    def _parse_anonymity(self, proxy_info):
        if proxy_info.startswith('N'):
            proxy_level_anonymity = 0
        elif proxy_info.startswith('A'):
            proxy_level_anonymity = 1
        elif proxy_info.startswith('H'):
            proxy_level_anonymity = 2
        return proxy_level_anonymity

    def _parse_proxy_type(self, proxy_info):
        try:
            proxy_type = proxy_info[2]
        except IndexError:
            proxy_type = proxy_info[1]
        return proxy_type

    def _parse_google_passed(self, proxy_line):
        if proxy_line.endswith('+'):
            return True
        return False

    def _parse_output_ip(self, proxy_type):
        if proxy_type.endswith('!'):
            return True
        return False

    def _parse_http_type(self, proxy_type):
        if proxy_type.startswith('S'):
            return 'https'
        return 'http'

    def before_handler(self, **kwargs):
        log.debug('Initializing flow processing...')

    def after_handler(self, **kwargs):
        log.debug('Flow processing performed!')

    def __enter__(self):
        self._initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val:
            log.warning(f'exc_type: {exc_type}')
            log.warning(f'exc_value: {exc_val}')
            log.warning(f'exc_traceback: {exc_tb}')

    def __repr__(self):
        return (
            f'ProxyListClient [' f'success={self._info.success} ' f'failure={self._info.failure}]'
        )
