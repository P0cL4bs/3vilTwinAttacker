from Plugin import PluginProxy
import logging
from core.utils import setup_logger

class noscroll(PluginProxy):
    ''' this module proxy not work noscroll on html page.'''
    _name          = 'noscroll'
    _activated     = False
    _instance      = None
    _requiresArgs  = False

    @staticmethod
    def getInstance():
        if noscroll._instance is None:
            noscroll._instance = noscroll()
        return noscroll._instance

    def __init__(self):
        self.args = None

    def LoggerInjector(self,session):
        setup_logger('injectionPage', './logs/AccessPoint/injectionPage.log',session)
        self.logging = logging.getLogger('injectionPage')

    def setInjectionCode(self, code,session):
        self.args = code
        self.LoggerInjector(session)

    def inject(self, data, url):
        injection_code = '''</head> <!-- Put an invisible div over everything -->
<div style="position:fixed;width:100%;height:100%;z-index:9001;opacity:0;"></div>'''
        self.logging.info("Injected: %s" % (url))
        return data.replace('</head>',injection_code)


