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
import sys
import json
import subprocess
import urllib.parse
from queue import Queue
from threading import Thread, Lock
from abc import ABC, abstractmethod

OPENSSLv11_EXECUTABLE_PATH = '/usr/bin/openssl11'
OPENSSLv11_SUPPORTED_PROTOCOLS = {
	'TLSv1'  : 'tls1',
	'TLSv1.1': 'tls1_1',
	'TLSv1.2': 'tls1_2',
	'TLSv1.3': 'tls1_3'
}

class WGThreadPool(ABC):
	def __init__(self, nthreads):
		self.lock = Lock()
		self.nthreads = nthreads
		self.queue = Queue()
		for i in range(nthreads):
			Thread(target=self._thead_func,
				daemon=True).start()

	def _thead_func(self):
		while True:
			task = self.queue.get(block=True)
			self.handler(task)
			self.queue.task_done()

	def add_task(self, task):
		self.queue.put(task, block=True)

	def wait_tasks(self):
		self.queue.join()

	@abstractmethod
	def handler(self,task):
		pass

class WGHostSSLAnalizer(WGThreadPool):
	def __init__(self, hostname, port):
		self.address = f'{hostname}:{port}'
		self.ciphers = {}
		self.report = {}
		WGThreadPool.__init__(self,
			nthreads=50)

	def openssl_load_available_ciphers(self):
		for name, proto in OPENSSLv11_SUPPORTED_PROTOCOLS.items():
			cmd = [
				OPENSSLv11_EXECUTABLE_PATH,
				'ciphers',
				f'-{proto}',
				'ALL:eNULL'
			]
			process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
				stderr=subprocess.PIPE)
			output, _ = process.communicate()
			if process.wait():
				continue
			output = output.decode().strip()
			self.ciphers[name] = output.split(':')

	def openssl_analize_cipher(self, proto, cipher):
		cmd = [
			OPENSSLv11_EXECUTABLE_PATH,
			's_client',
			'-connect',
			self.address,
			'-cipher',
			cipher,
			f'-{OPENSSLv11_SUPPORTED_PROTOCOLS[proto]}'
		]
		process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output, _ = process.communicate()
		if process.wait():
			print(f'[{proto}:{cipher}] FAILED!')
			return
		with self.lock:
			try:
				self.report[proto].append(cipher)
			except KeyError:
				self.report[proto] = [cipher]
		print(f'[{proto}:{cipher}] OK!')

	def handler(self, task):
		proto, cipher = task
		self.openssl_analize_cipher(proto, cipher)

	def run(self):
		self.openssl_load_available_ciphers()
		for proto, ciphers in self.ciphers.items():
			for cipher in ciphers:
				self.add_task((proto, cipher))
		self.wait_tasks()
		return self.report

def main():
	analizer = WGHostSSLAnalizer(sys.argv[1], sys.argv[2])
	status = analizer.run()
	print(json.dumps(status, indent=4))

if __name__ == '__main__':
	main()

# end-of-file #
