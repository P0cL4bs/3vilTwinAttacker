from Plugin import PluginProxy
import logging
from core.utils import setup_logger

class title(PluginProxy):
    ''' this module proxy add title on html page.'''
    _name          = 'title_changer'
    _argsname      = 'Title:'
    _activated     = False
    _instance      = None
    _requiresArgs  = True

    @staticmethod
    def getInstance():
        if title._instance is None:
            title._instance = title()
        return title._instance

    def __init__(self):
        self.title = None

    def LoggerInjector(self,session):
        setup_logger('injectionPage', './logs/AccessPoint/injectionPage.log',session)
        self.logging = logging.getLogger('injectionPage')

    def setInjectionCode(self, code,session):
        self.title = code
        self.LoggerInjector(session)

    def inject(self, data, url):
        injection_code = '<title> {} '.format(self.title)
        self.logging.info("Injected: %s" % (url))
        return data.replace('<title>',injection_code)
