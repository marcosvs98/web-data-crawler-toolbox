import datetime
import json
import logging
import sys
import urllib.parse
from abc import ABC, abstractmethod
from queue import Queue
from threading import Thread

import dns.resolver

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


class DomainScanner(ThreadPool):
    def __init__(self, url, nthreads, limit=0):
        uri = urllib.parse.urlparse(url)
        domain = uri.netloc if uri.scheme else uri.path
        self.domain = domain.lstrip('www.')
        self.results = {}
        self.limit = limit
        ThreadPool.__init__(self, nthreads)

    def dns_resolve(self, hostname, nameserver=None):
        try:
            r = dns.resolver.Resolver()
            if nameserver:
                r.nameservers = [nameserver]
            return [str(ip) for ip in r.resolve(hostname)]
        except dns.exception.DNSException:
            return []

    def save(self):
        filename = f'./subdomain-scanner-{self.domain}.json'
        with open(filename, 'w') as f:
            json.dump(
                {'timestamp': datetime.datetime.now().isoformat(), 'scan-results': self.results},
                f,
                indent=4,
            )
        log.debug(f"Report written: '{filename}'")

    def run(self):
        self.add_task(self.domain)
        with open('./subdomains/top100000.txt') as f:
            for n, subdomain in enumerate(f, 1):
                if (self.limit > 0) and (n >= self.limit):
                    break
                self.add_task(f'{subdomain.strip()}.{self.domain}')
        self.wait_tasks()
        return self.results

    def handler(self, subdomain):
        ips = self.dns_resolve(subdomain, nameserver='8.8.8.8')
        if ips:
            log.info(f'{subdomain}: {ips}')
            self.results[subdomain] = ips


def main():
    scanner = DomainScanner(url=sys.argv[1], nthreads=50)
    scanner.run()
    scanner.save()


if __name__ == '__main__':
    main()
