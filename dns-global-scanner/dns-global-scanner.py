import csv
import datetime
import io
import json
import logging
import sys
import urllib.parse
from abc import ABC, abstractmethod
from queue import Queue
from threading import Thread

import dns.resolver
import requests

log = logging.getLogger(__name__)

logging.basicConfig(
    **{
        'format': f'[%(asctime)s.%(msecs)03d][%(threadName)s]: %(message)s',
        'datefmt': '%Y-%m-%d %H:%M:%S',
        'level': logging.DEBUG,
        'stream': sys.stdout,
    }
)


class ThreadPool(ABC):
    def __init__(self, nthreads):
        self.nthreads = nthreads
        self.queue = Queue()
        for i in range(nthreads):
            Thread(target=self._thread_func, daemon=True).start()

    def _thread_func(self):
        while True:
            task = self.queue.get(block=True)
            self.handler(task)
            self.queue.task_done()

    def add_task(self, task):
        self.queue.put(task, block=True)

    def wait_tasks(self):
        self.queue.join()

    @abstractmethod
    def handler(self, task):
        pass


class DNSGlobalScanner(ThreadPool):
    def __init__(self, url, nthreads=25):
        uri = urllib.parse.urlparse(url)
        self.domain = uri.netloc if uri.scheme else uri.path
        self.report = []
        self.countries = self.get_countries()
        ThreadPool.__init__(self, nthreads)

    def get_countries(self):
        try:
            with open('./countries.json') as f:
                return json.load(f)
        except OSError:
            return {}

    def nameservers(self):
        try:
            resp = requests.get('https://public-dns.info/nameservers.csv', timeout=30)
        except (requests.RequestException, requests.exceptions.RequestException):
            return []
        for record in csv.DictReader(io.StringIO(resp.text)):
            record = {
                k: v
                for k, v in record.items()
                if k in ['ip_address', 'name', 'country_code', 'city', 'as_org']
            }
            record['country_name'] = self.countries.get(record['country_code'])
            yield record

    def dns_lookup(self, ip, nameserver=None):
        try:
            r = dns.resolver.Resolver()
            if nameserver:
                r.nameservers = [nameserver]
            return [str(hostname).strip('.') for hostname in r.resolve_address(ip)]
        except (dns.exception.DNSException, AttributeError):
            return []

    def dns_resolve(self, hostname, nameserver=None):
        try:
            r = dns.resolver.Resolver()
            if nameserver:
                r.nameservers = [nameserver]
            return {str(ip): self.dns_lookup(str(ip), nameserver) for ip in r.resolve(hostname)}
        except dns.exception.DNSException:
            return {}

    def run(self):
        for nameserver in self.nameservers():
            self.add_task(nameserver)
        self.wait_tasks()
        ips = {}
        for nameserver in self.report:
            for ip, hosts in nameserver['answers'].items():
                if ip not in ips:
                    ips[ip] = []
                for host in hosts:
                    if host not in ips[ip]:
                        ips[ip].append(host)
        self.report.sort(key=lambda k: -len(k['answers']))
        self.report.insert(
            0,
            {
                'timestamp': datetime.datetime.now().isoformat(),
                'domain': self.domain,
                'all-answers': ips,
            },
        )
        return self.report

    def save(self):
        filename = f'./dns-global-{self.domain}.json'
        with open(filename, 'w') as f:
            json.dump(self.report, f, indent=4)
        log.debug(f"Report written: '{filename}'")

    def handler(self, nameserver):
        log.debug(
            f"{nameserver['ip_address']} - "
            f"{nameserver['as_org']} - "
            f"[{nameserver['country_name']} / "
            f"{nameserver['country_code']}]"
        )
        nameserver['domain'] = self.domain
        nameserver['answers'] = self.dns_resolve(self.domain, nameserver['ip_address'])
        if nameserver['answers']:
            self.report.append(nameserver)


def main():
    scanner = DNSGlobalScanner(url=sys.argv[1], nthreads=50)
    scanner.run()
    scanner.save()


if __name__ == '__main__':
    main()
