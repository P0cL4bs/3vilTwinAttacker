class PluginProxy(object):
    '''' Main class modules '''

    def inject(self, data, url):
        ''' called injection data on responseTamperer'''
        raise NotImplementedError

    def setInjectionCode(self, code):
        ''' function set content data to injection'''
        raise NotImplementedError