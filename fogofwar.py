#! /usr/bin/python3

import logging
import logging.handlers
import threading
import time
import syslog
import sys
import os
import queue
import socketserver

from config import configulator
from fog import fogcontrol
from tables import tablescontrol
from honeyports import honeyport
from history import historycontrol


def main():
    # read config
    config = configulator.configulator().readconfig()

    # set up the logging subsystem
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger(__name__)
    sh = logging.handlers.SysLogHandler(
        address="/dev/log", facility=config.get("LOGS", "facility")
    )
    sh.setLevel(logging.DEBUG)
    log.addHandler(sh)
    log.info("FogofWar: Logging Online")

    if os.geteuid() != 0:
        log.info("FogofWar: You need to have root privileges to run this script.")
        exit("You need to have root privileges to run this script.")

    # set up the queue
    log.info("FogofWar: Initializing Queue")
    msgqueue = queue.Queue()
    log.info("FogofWar: Initializing Queue Complete")

    try:
        # starting iptables autocrontrol
        log.info("FogofWar: IPTables controller")
        tables = tablescontrol.Controller(config, msgqueue, log)
        tables.start()
        log.info("FogofWar: IPTables controller started")

        # starting history autocontrol
        log.info("FogofWar: History controller")
        history = historycontrol.Controller(config, msgqueue, log)
        history.start()
        log.info("FogofWar: History controller started")

        control = fogcontrol.Controller(
            config=config, msgqueue=msgqueue, log=log, tables=tables, history=history
        )

        # starting iptables autocontrol

        control.start()
        log.info("FogofWar: Fog controller started")

        # control message
        # control.mailbox.put("Mailbox One")
        # control.stop()

        ports = config.get("HONEY", "ports").split(",")

        serverlist = []
        for port in ports:
            log.info("FogofWar: Listening on port %s" % (port))
            port = int(port)
            try:
                server = honeyport.v6ThreadingTCPServer(
                    ("::", port), honeyport.SocketListener, msgqueue
                )
            except Exception as e:
                log.error(
                    "FogofWar: Could not instantiate an instance for port %s. Already bound?"
                    % port
                )
                pass
            server.msgqueue = msgqueue
            server.log = log
            server.port = port
            serverlist.append(server)
            try:
                listener = threading.Thread(target=server.serve_forever)
                listener.setDaemon(True)
                listener.start()
            except Exception as e:
                log.error(
                    "FogofWar: Error Could not start thread %s: %s port %s"
                    % (str(e), "", port)
                )
                pass

        log.info("FogofWar: Running...")

        while True:
            try:
                time.sleep(100000)
            except KeyboardInterrupt:
                for server in serverlist:
                    server.shutdown()
                    server.server_close()
                    log.info("FogofWar: Shutdown Honeyport %s" % (server.port))
                tables.stop()
                control.stop()
                history.stop()
                logging.shutdown()
                sys.exit()
                # return

    except Exception as e:
        log.error("FogofWar: Error General exception: " + format(e))

        for server in serverlist:
            server.shutdown()
            server.server_close()
            log.info("FogofWar: Shutdown Honeyport %s" % (server.port))
        tables.stop()
        control.stop()
        history.stop()
        logging.shutdown()
        sys.exit()
        # return


if __name__ == "__main__":
    main()
