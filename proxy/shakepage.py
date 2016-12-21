from Plugin import PluginProxy
import logging
from core.utils import setup_logger

class shake(PluginProxy):
    ''' this module proxy added javascript to shake page.'''
    _name          = 'shake_page'
    _activated     = False
    _instance      = None
    _requiresArgs  = False

    @staticmethod
    def getInstance():
        if shake._instance is None:
            shake._instance = shake()
        return shake._instance

    def __init__(self):
        self.args = None

    def LoggerInjector(self,session):
        setup_logger('injectionPage', './logs/AccessPoint/injectionPage.log',session)
        self.logging = logging.getLogger('injectionPage')

    def setInjectionCode(self, code,session):
        self.args = code
        self.LoggerInjector(session)

    def inject(self, data, url):
        injection_code = '''<script>
window.onload=function() {
    var move=document.getElementsByTagName("body")[0];
    setInterval(function() {
        move.style.marginTop=(move.style.marginTop=="4px")?"-4px":"4px";
    }, 5);
}
</script>'''
        self.logging.info("Injected: %s" % (url))
        return data.replace('</body>','{}</body>'.format(injection_code))