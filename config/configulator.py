#
#
# config file definitions
#
#


import os
import configparser

class configulator:
	def readconfig(self):
		config = configparser.ConfigParser()
		config.read('fogofwar.cfg')

		return config
