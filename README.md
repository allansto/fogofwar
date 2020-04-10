<h1>Fog of War</h1>
<h2>Honeyports Program</h2>

<p>This is a scanner detector built to be scalable, robust, and understand both IPv4 and IPv6</p>
<p>This was inspired by and originally based off the most excellent work by TrustedSec: Artillery.</p>


<h2> systemd start file</h2>
<pre>
[Unit]
Description=FogofWar
After=syslog.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/fogofwar
ExecStart=/opt/fogofwar/fogofwar.py
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
</pre>

