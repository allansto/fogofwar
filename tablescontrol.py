#! /usr/bin/python

import time
import threading
import queue
import sys
import re
import subprocess
import logging
import os
import netaddr

class Controller(threading.Thread):
	def __init__(self,config,msgqueue,log):

		threading.Thread.__init__(self)
		self.config = config
		self.msgqueue = msgqueue
		self.mailbox = queue.Queue()
		self.log = log
		self.create_iptables_subset()

		self.qreleases = []
		return

	def run(self):
		#DROP       all  --  192.168.1.24         0.0.0.0/0             /* ttl=144138170230 */
		#DROP       all      fe80::c68e:8fff:fef7:273d  ::/0             /* ttl=1441389778 */

		time.sleep(60)

		items = re.compile('DROP\s+all\s+--\s+(\S+)\s+0.0.0.0/0\s+/\*\s+ttl=(\d+)\s+\*/',re.LOCALE)
		itemsv6 = re.compile('DROP\s+all\s+(\S+)\s+::/0\s+/\*\s+ttl=(\d+)\s+\*/',re.LOCALE)

		while True:
			# check for shutdown signal
			if (self.mailbox.qsize() >0):
				sd = self.mailbox.get()
				if (sd == 'shutdown'):
					self.log.info("FogofWar: Tables controller shutting down")
					return

			epoch_time = int(time.time())
			for line in self.getIPTables():
				if (items.match(line)):
					m = items.match(line)
					ip = m.group(1)
					ttl = m.group(2)
					ipttl = "%s %s"%(ip,ttl)
					if (epoch_time > int(ttl) and ipttl not in self.qreleases):
						self.qreleases.append(ipttl)
						self.msgqueue.put("Release: %s %s"%(ip,ttl))

			for line in self.getIP6Tables():
				if (itemsv6.match(line)):
					m = itemsv6.match(line)
					ip = m.group(1)
					ttl = m.group(2)
					ipttl = "%s %s"%(ip,ttl)
					if (epoch_time > int(ttl) and ipttl not in self.qreleases):
						self.qreleases.append(ipttl)
						self.msgqueue.put("Release: %s %s"%(ip,ttl))

			time.sleep(2)

	def stop(self):
		self.mailbox.put("shutdown")
		self.join()

#
# support utilities
#

	def is_valid_ipv4(self,ip):
		ver = 0
		try:
			x = netaddr.IPAddress(ip)
			ver = x.version
		except:
			pass

		if (ver == 4):
			return True
		else:
			return False

	def is_valid_ipv6(self,ip):
		ver = 0
		try:
			x = netaddr.IPAddress(ip)
			ver = x.version
		except:
			pass

		if (ver == 6):
			return True
		else:
			return False

	def is_valid_subnet(self,net):
		n = netaddr.IPNetwork(net)
		return True

	def is_ip_in_subnet(self,ip,net):
		try:
			if (net.broadcast is None):
				if (ip == net.network):
					return True
			else:
				if (ip >= net.network and ip <= net.broadcast):
					return True
		except TypeError:
			print('Problematic: ',ip,net.network,net.broadcast)
			

	def normalize_ip(self,ip):
		# if it is a v6 address, check for an remove interface
		ip = ip.split('%')[0]

		# if it is a v4 embedded in a v6 address, convert it
		if (self.is_valid_ipv6(ip)):
			testip = netaddr.IPAddress(ip)
			try:
				ip = testip.ipv4()
			except:
				pass

		return(ip)

#
# Return an iterator for each table
#

	def getIPTables(self):
		try:
			p = subprocess.Popen(["/sbin/iptables","-n","-L","FOG"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
			return iter(p.stdout.readline, '')
		except subprocess.CalledProcessError as e:
			self.log.error("FogofWar: Error Could not read v4 iptables: %s" %str(e))
			return ()

	def getIP6Tables(self):
		try:
			p = subprocess.Popen(["/sbin/ip6tables","-n","-L","FOG"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
			return iter(p.stdout.readline, '')
		except subprocess.CalledProcessError as e:
			self.log.error("FogofWar: Error Could not read v6 iptables: %s" %str(e))
			return ()


#
# Create the FOG tables for each v4 and v6 
# unless it already exists
#

	def create_iptables_subset(self):
		# create the subchain if it does not already exist
		dn = open(os.devnull,"w+")

		# for ipv4
		p=subprocess.call(["/sbin/iptables","-L","FOG"],stdout=dn)
		if (p > 0):
			self.log.info("FogofWar: IPv4 FOG chain does not exist. Creating...")
			subprocess.check_output(["/sbin/iptables","-N","FOG"])
			subprocess.check_output(["/sbin/iptables","-F","FOG"])
			subprocess.check_output(["/sbin/iptables","-I","INPUT","-j","FOG"])

		# for ipv6
		p=subprocess.call(["/sbin/ip6tables","-L","FOG"],stdout=dn)
		if (p > 0):
			self.log.info("FogofWar: IPv6 FOG chain does not exist. Creating.")
			subprocess.check_output(["/sbin/ip6tables","-N","FOG"])
			subprocess.check_output(["/sbin/ip6tables","-F","FOG"])
			subprocess.check_output(["/sbin/ip6tables","-I","INPUT","-j","FOG"])

#
# Ban an IP for X seconds
#

	def ban(self,ip,sec):
		# get epoch time
		epoch_time = int(time.time())

		if ( int(sec) < 0 ):
			# is it valid
			if (self.is_valid_ipv4(ip)):
				try:
					subprocess.check_output(["/sbin/iptables","-w","5","-I","FOG","1","-s","%s" %ip,"-j","DROP"],universal_newlines=True)
				except:
					self.log.error("FogofWar: Error Could not ban: %s" %str(e))
					pass
			elif (self.is_valid_ipv6(ip)):
				try:
					subprocess.check_output(["/sbin/ip6tables","-w","5","-I","FOG","1","-s","%s" %ip,"-j","DROP"],universal_newlines=True)
				except:
					self.log.error("FogofWar: Error Could not ban: %s" %str(e))
					pass
		else:
			duration = int(epoch_time) + int(sec)
			if (self.is_valid_ipv4(ip)):
				try:
					subprocess.check_output(["/sbin/iptables","-w","5","-I","FOG","1","-s","%s" %ip,"-j","DROP","-m","comment","--comment","ttl=%s" %duration],universal_newlines=True)
				except Exception as e:
					self.log.error("FogofWar: Error Could not ban: %s" %str(e))
					pass
			elif (self.is_valid_ipv6(ip)):
				try:
					subprocess.check_output(["/sbin/ip6tables","-w","5","-I","FOG","1","-s","%s" %ip,"-j","DROP","-m","comment","--comment","ttl=%s" %duration],universal_newlines=True)
				except:
					self.log.error("FogofWar: Error Could not ban: %s" %str(e))
					pass


#
# Unban an IP
#

	def unban(self,ip,ttl):
		# iptables -D FOG -s 192.168.1.24 -j DROP -m comment --comment ttl=144137859230

		if (self.is_valid_ipv4(ip)):
			try:
				subprocess.check_output(["/sbin/iptables","-D","FOG","-w","-s","%s" %ip,"-j","DROP","-m","comment","--comment","ttl=%s" %ttl],universal_newlines=True)
				self.qreleases.pop(self.qreleases.index("%s %s"%(ip,ttl)))
			except subprocess.CalledProcessError as e:
				self.log.error("FogofWar: Error: %s" %str(e))
				pass
		else:
			try:
				subprocess.check_output(["/sbin/ip6tables","-D","FOG","-w","-s","%s" %ip,"-j","DROP","-m","comment","--comment","ttl=%s" %ttl],universal_newlines=True)
				self.qreleases.pop(self.qreleases.index("%s %s"%(ip,ttl)))
			except subprocess.CalledProcessError as e:
				self.log.error("FogofWar: Error: %s" %str(e))
				pass


