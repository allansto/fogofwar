#! /usr/bin/python

import time
import threading
import queue as queue
import sys
import socket
from socket import error as HoneySocketError
import socketserver
import random
import os
import string

class SocketListener((socketserver.BaseRequestHandler)):

	def __init__(self, request, client_address, server):
		self.request = request
		self.client_address = client_address
		self.server = server
		self.msgqueue = self.server.msgqueue
		self.log = self.server.log
		self.setup()

		try:
			self.handle()
		finally:
			self.finish()

	def handle(self):
		pass
		

	def setup(self):
		self.length = random.randint(5,100000)
		#self.fake_string = os.urandom(int(self.length))
		self.fake_string = ''.join(random.choice(string.printable) for _ in range(self.length))
		try:
			self.request.send(self.fake_string.encode('utf-8'))
		except HoneySocketError as e:
			if (e.errno == socket.errno.ECONNRESET):
				pass
			elif (e.errno == socket.errno.ENOTCONN):
				pass
			else:
				self.log.error("FogofWar: HoneySocketError: %s"%str(e))
				raise

		[self.sip, self.sport, self.x, self.y] = self.client_address
		[self.dip, self.dport, self.x, self.y] = self.request.getsockname()
		self.msgqueue.put("Connect: %s %s %s %s" % (self.sip,self.sport,socket.gethostname(),self.dport))
		self.log.debug("FogofWar: Connection [%s]:%s to [%s]:%s" % (self.sip,self.sport,self.dip,self.dport))

		try:
			self.request.shutdown(socket.SHUT_RDWR)
			self.request.close()
		except HoneySocketError as e:
			if (e.errno == socket.errno.ECONNRESET):
				pass
			elif (e.errno == socket.errno.ENOTCONN):
				pass
			else:
				raise



class v6ThreadingTCPServer(socketserver.ThreadingTCPServer):
	address_family = socket.AF_INET6
	allow_reuse_address = True
