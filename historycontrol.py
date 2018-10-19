#! /usr/bin/python

import time
import threading
import queue
import sys
import sqlite3

class Controller(threading.Thread):
	def __init__(self,config,msgqueue,log):
		threading.Thread.__init__(self)
		self.config = config
		self.msgqueue = msgqueue
		self.mailbox = queue.Queue()
		self.log = log
		return

	def run(self):
		self.conn = sqlite3.connect('fogdatabase.db')
		self.history = self.conn.cursor()
		self.history.execute('CREATE TABLE IF NOT EXISTS history (timestamp REAL,address TEXT,author TEXT,message TEXT)')
		self.conn.commit()
		while True:

			if (self.mailbox.qsize() > 0 ):
				sd = self.mailbox.get()
				if (sd == 'shutdown'):
					self.log.info("FogofWar: Database Controller shutting down.")
					if self.conn:
						self.conn.close()
					return
				else:
					(action,timestamp,ip,author,original_message) = sd.split(" ",4)
					self.addToDatabase(timestamp,ip,author,original_message)
					
				
			time.sleep(1)

	def stop(self):
		self.mailbox.put("shutdown")
		self.join()


	def addToDatabase(self,timestamp,address,author,message):
		self.history.execute('INSERT INTO history (timestamp,address,author,message) VALUES (?,?,?,?)',(timestamp,address,author,message))
		self.conn.commit()
		return

	def getAddressCount(self,address):
		con = sqlite3.connect("fogdatabase.db")
		try:
			num = con.execute('SELECT count(*) FROM history WHERE address = ?',(address,)).fetchone()
		except:
			num = 0
			pass
		con.close()
		return num


	def getAuthorsByAddress(self,address):
		con = sqlite3.connect("fogdatabase.db")
		try:
			authors = con.execute('SELECT DISTINCT author FROM history WHERE address = ?',(address,)).fetchall()
		except:
			authors = ""
			pass
		con.close()
		return authors
