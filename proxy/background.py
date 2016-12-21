from Plugin import PluginProxy
import logging
from core.utils import setup_logger

class background(PluginProxy):
    ''' this module proxy add image background on html page.'''
    _name          = 'background'
    _argsname      = 'Url:'
    _activated     = False
    _instance      = None
    _requiresArgs  = True

    @staticmethod
    def getInstance():
        if background._instance is None:
            background._instance = background()
        return background._instance

    def __init__(self):
        self.url_image = None

    def LoggerInjector(self,session):
        setup_logger('injectionPage', './logs/AccessPoint/injectionPage.log',session)
        self.logging = logging.getLogger('injectionPage')

    def setInjectionCode(self, code,session):
        self.url_image = code
        self.LoggerInjector(session)

    def inject(self, data, url):
        injection_code = '''<style>
        body  {
        background-image: url("%s");
        }
        </style>
        </head>'''%(self.url_image)
        self.logging.info("Injected: %s" % (url))
        return data.replace('</head>',injection_code)
