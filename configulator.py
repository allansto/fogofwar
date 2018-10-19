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
		# if it does not exist write some defaults to file
		if not os.path.isfile('fogofwar.cfg'):
			# honey section
			config.add_section('HONEY')
			config.set('HONEY','ports',"135,445,22,1433,3389,8080,21,5900,25,53,110,1723,1337,10000,5800,44443,5060")

			#log section
			config.add_section('LOGS')
			config.set('LOGS','facility','LOG_LOCAL7')

			#control section
			config.add_section('CONTROL')
			config.set('CONTROL','whitelist','127.0.0.1/32')
			config.set('CONTROL','sensorname','Fog11')

			#quarantine section
			config.add_section('QUARANTINE')
			config.set('QUARANTINE','quarantine','on')
			config.set('QUARANTINE','seconds','3600')

			#quarantine section
			config.add_section('QBGP')
			config.set('QBGP','qbgp','off')
			config.set('QBGP','username','')
			config.set('QBGP','password','')
			config.set('QBGP','host','')
			config.set('QBGP','port','')

			# write out the file
			configfile = open('fogofwar.cfg','wb')
			config.write(configfile)
			configfile.close()
	
		config.read('fogofwar.cfg')

		return config
