from threading import Thread
from core.utility.collection import  SettingsINI
try:
    from mitmproxy import controller,flow
    from plugins.extension import *
except ImportError:
    pass
import core.utility.constants as C


"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for Pumpkin-Proxy Core.

Copyright:
    Copyright (C) 2015-2017 Marcos Nesster P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

class ThreadController(Thread):
    def __init__(self,main ,parent=None):
        super(ThreadController, self).__init__(parent)
        self.main = main

    def run(self):
        try:
            flow.FlowMaster.run(self.main)
        except :
            self.main.shutdown()

    def stop(self):
        self.main.shutdown()


class MasterHandler(flow.FlowMaster):
    def __init__(self,opts, server,state,session):
        flow.FlowMaster.__init__(self,opts, server,state)
        self.config  = SettingsINI(C.PUMPPROXY_INI)
        self.session = session
        self.plugins = []
        self.initializePlugins()
        
    def run(self,send):
        self.sendMethod = send
        for plugin in self.plugins:
            plugin.send_output = self.sendMethod
        self.thread = ThreadController(self)
        self.thread.start()

    def disablePlugin(self,name, status):
        ''' disable plugin by name '''
        plugin_on = []
        if status:
            for plugin in self.plugins:
                plugin_on.append(plugin.Name)
            if name not in plugin_on:
                for p in self.plugin_classes:
                    pluginconf = p()
                    if  pluginconf.Name == name:
                        pluginconf.send_output = self.sendMethod
                        print('PumpkinProxy::{0:17} status:On'.format(name))
                        self.plugins.append(pluginconf)
        else:
            for plugin in self.plugins:
                if plugin.Name == name:
                    print('PumpkinProxy::{0:17} status:Off'.format(name))
                    self.plugins.remove(plugin)

    def initializePlugins(self):
        self.plugin_classes = plugin.PluginTemplate.__subclasses__()
        for p in self.plugin_classes:
            if self.config.get_setting('plugins',p().Name,format=bool):
                print('PumpkinProxy::{0:17} status:On'.format(p().Name))
                self.plugins.append(p())
        # initialize logging in all plugins enable
        #for instance in self.plugins:
        #    instance.init_logger(self.session)

    @controller.handler
    def request(self, flow):
        '''
        print "-- request --"
        print flow.__dict__
        print flow.request.__dict__
        print flow.request.headers.__dict__
        print "--------------"
        print
        '''
        try:
            for p in self.plugins:
                p.request(flow)
        except Exception:
            pass

    @controller.handler
    def response(self, flow):

        '''
        print
        print "-- response --"
        print flow.__dict__
        print flow.response.__dict__
        print flow.response.headers.__dict__
        print "--------------"
        print
        '''
        try:
            for p in self.plugins:
                p.response(flow)
        except Exception:
            pass