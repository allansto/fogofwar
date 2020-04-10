#! /usr/bin/python3

import time
import threading
import queue
import sys

# import netaddr
import ipaddress
import sqlite3
import requests
import json


class Controller(threading.Thread):
    def __init__(self, config, msgqueue, log, tables, history):
        threading.Thread.__init__(self)
        self.config = config
        self.msgqueue = msgqueue
        self.mailbox = queue.Queue()
        self.log = log
        self.tables = tables
        self.history = history
        self.sess = requests.Session()

        try:
            self.sensorname = self.config.get("CONTROL", "sensorname")
        except:
            self.sensorname = socket.gethostname()
        if self.sensorname == "":
            self.sensorname = socket.gethostname()

        return

    def run(self):
        self.DedupInit()
        while True:

            if self.mailbox.qsize() > 0:
                sd = self.mailbox.get()
                if sd == "shutdown":
                    self.log.info("FogofWar: Fog Controller shutting down.")
                    return

            time.sleep(0.01)
            if self.msgqueue.qsize() > 0:

                # self.DedupCount()
                self.DedupClear()

                msg = self.msgqueue.get()
                action = msg.split(" ")[0]
                if action == "Release:":
                    self.release(msg)
                elif action == "Intel:":
                    self.intel(msg)
                elif action == "Connect:":
                    self.connect(msg)
                else:
                    self.log.error("FogofWar: Unknown Command : %s" % msg)
                self.msgqueue.task_done()

    def stop(self):
        self.mailbox.put("shutdown")
        self.join()

    def release(self, msg):
        (action, ip, ttl) = msg.split(" ")
        self.tables.unban(ip, ttl)
        self.log.info("FogofWar: Released [%s] %s" % (ip, ttl))
        return

    def connect(self, msg):
        (action, sip, sport, dip, dport) = msg.split(" ")
        sip = self.tables.normalize_ip(sip)

        self.log.debug("FogofWar: MSG = %s" % (action))

        # check to see if we have processed this recently
        c = self.DedupCheck(sip)
        if c > 0:
            self.log.info("FogofWar: Duplicate %s (%s)" % (sip, self.DedupCount()))
            return

        # whitelist?
        if self.is_whitelisted(sip, self.config):
            self.log.info("FogofWar: Whitelisted [%s]" % (sip))
            # whitelist means do nothng else
            return

        # quarantine?
        if self.config.get("QUARANTINE", "quarantine") == "on":
            # seconds = -1 is block forever
            self.tables.ban(sip, self.config.get("QUARANTINE", "seconds"))

        # QBGP active?
        if self.config.get("QBGP", "qbgp") == "on" and not self.is_whitelisted(
            sip, self.config
        ):
            payload = {}
            payload["address"] = str(sip)
            payload["sport"] = sport
            payload["dport"] = dport
            payload["sensor"] = self.sensorname
            payload["reason"] = "tcp/%s Attacked a monitored resource" % str(dport)
            try:
                r = self.sess.put(
                    "https://%s:%s@%s:%s/quarantine"
                    % (
                        self.config.get("QBGP", "username"),
                        self.config.get("QBGP", "password"),
                        self.config.get("QBGP", "host"),
                        self.config.get("QBGP", "port"),
                    ),
                    verify=False,
                    data=json.dumps(payload),
                )
                self.log.debug("FogofWar: QBGP %s" % (json.dumps(payload)))
                self.log.debug("FogofWar: QBGP Response %s" % (r.json()))
                self.log.info(
                    "FogofWar: QBGP [%s] in %s seconds" % (sip, r.json()["ElapsedTime"])
                )
            except:
                pass

            # self.log.debug("FogofWar: QBGP %s" % (json.dumps(payload)))
            # self.log.info("FogofWar: QBGP %s" % (sip))

        # Log it.
        self.DedupAdd(sip)
        self.log.info(
            "FogofWar: Banned [%s]:%s to %s:%s" % (sip, sport, self.sensorname, dport)
        )
        return

    def intel(self, msg):
        self.log.info("FogofWar: %s" % msg)
        self.history.mailbox.put(msg)
        return

    #
    # support defs
    #

    def is_whitelisted(self, ip, c):
        wl = c.get("CONTROL", "whitelist")
        wips = wl.split(",")
        for wip in wips:
            if self.tables.is_ip_in_subnet(
                ip=ipaddress.ip_address(ip), net=ipaddress.ip_network(wip)
            ):
                return True
        return False

    def DedupInit(self):
        self.conn = sqlite3.connect(":memory:")
        self.dedup = self.conn.cursor()
        self.dedup.execute(
            "CREATE TABLE IF NOT EXISTS dedup (timestamp REAL, address TEXT)"
        )
        self.conn.commit()
        return

    def DedupClear(self):
        # clear everything older than 60 seconds
        old = time.time() - 60
        self.dedup.execute("DELETE from dedup where timestamp < ?", (old,))
        self.conn.commit()
        return

    def DedupAdd(self, ip):
        now = time.time()
        self.dedup.execute(
            "INSERT into dedup (timestamp,address) values (?,?)", (now, str(ip))
        )
        self.conn.commit()
        return

    def DedupCount(self):
        self.dedup.execute("select count(*) from dedup")
        count = self.dedup.fetchone()[0]
        return count

    def DedupCheck(self, ip):
        self.dedup.execute("select count(*) from dedup where address = ?", (str(ip),))
        c = self.dedup.fetchone()[0]
        return c
