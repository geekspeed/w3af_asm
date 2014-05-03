"""
xml_f5asm.py

Copyright 2006 Andres Riancho

This file is part of w3af, http://w3af.org/ .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
import base64
import os
import sys
import time
import xml.dom.minidom
import itertools

from functools import partial

import w3af.core.data.kb.config as cf
import w3af.core.data.kb.knowledge_base as kb
#
from w3af.core.controllers.plugins.output_plugin import OutputPlugin
from w3af.core.controllers.misc import get_w3af_version
import w3af.core.controllers.output_manager as om
from w3af.core.data.misc.encoding import smart_str
from w3af.core.controllers.exceptions import BaseFrameworkException
from w3af.core.data.db.history import HistoryItem
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_types import OUTPUT_FILE
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.url.HTTPRequest import HTTPRequest

class xml_f5asm(OutputPlugin):
    """
    Create a file for import into F5's ASM platform

    :author: John Stauffacher ( @g33kspeed )
    """
    def __init__(self):
        OutputPlugin.__init__(self)

        # These attributes hold the file pointers
        self._file = None

        # User configured parameters
        self._file_name = '/tmp/f5_asm_import.xml'
        self._timeFormat = '%a %b %d %H:%M:%S %Y'
        self._longTimestampString = str(
            time.strftime(self._timeFormat, time.localtime()))
        self._timestampString = str(int(time.time()))

        # List with additional xml elements
        # xml
        # HistoryItem to get requests/responses
        self._history = HistoryItem()
	self._attack_type = {}
	# attack type matrix 
	self._attack_type["US Social Security"] = "Information Leakage - SSN"
	self._attack_type["XPATH"] = "XPath Injection"
	self._attack_type["Response splitting"] = "HTTP Response Splitting"
	self._attack_type["path disclosure"] = "Path Traversal"
	self._attack_type["Cross Site Request Forgery"] = "Cross-site Request Forgery"
	self._attack_type["SQL injection"] = "SQL-Injection"
	self._attack_type["credit card number"] = "Information Leakage - Credit Card"
	self._attack_type["Cross Site Scripting"] = "Cross Site Scripting (XSS)"
	self._attack_type["OS Commanding"] = "Command Execution"
	self._attack_type["SSI"] = "Server Side Code Injection"
	self._attack_type["input injection"] = "Injection Attempt"
	self._attack_type["LDAP injection"] = "LDAP Injection"
	self._attack_type["remote file inclusion"] = "Remote File Include"
	self._attack_type["file upload"] = "Malicious File Upload"
	self._attack_type["authentication cred"] = "Brute Force Attack"
	self._attack_type["requires authentication"] = "Authentication/Authorization Attacks"
	self._attack_type["buffer-overflow"] = "Buffer Overflow"
	# start xml file
	self._asmfile = xml.dom.minidom.Document()
	self._topElement = self._asmfile.createElement("scanner_vulnerabilities")
	self._topElement.setAttribute("version", self._timestampString)


    def _init(self):
        self._file_name = os.path.expanduser(self._file_name)
        try:
            self._file = open(self._file_name, "w")
        except IOError, io:
            msg = 'Can\'t open report file "%s" for writing, error: %s.'
            raise BaseFrameworkException(msg % (os.path.abspath(self._file_name),
                                       io.strerror))
        except Exception, e:
            msg = 'Can\'t open report file "%s" for writing, error: %s.'
            raise BaseFrameworkException(msg % (os.path.abspath(self._file_name), e))

    def do_nothing(self, *args, **kwds):
        pass
    debug = information = vulnerability = console = log_http = do_nothing

    def error(self, message, new_line=True):
        """
        This method is called from the output object. The output object was called
        from a plugin or from the framework. This method should take an action
        for error messages.
        """
        
        
    def set_options(self, option_list):
        """
        Sets the Options given on the OptionList to self. The options are the
        result of a user entering some data on a window that was constructed
        using the XML Options that was retrieved from the plugin using
        get_options()

        This method MUST be implemented on every plugin.

        :return: No value is returned.
        """
        self._file_name = option_list['output_file'].get_value()

    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        ol = OptionList()

        d = 'File name where this plugin will write to'
        o = opt_factory('output_file', self._file_name, d, OUTPUT_FILE)
        ol.add(o)

        return ol

    
    def log_enabled_plugins(self, pluginsDict, optionsDict):
        """
        This method is called from the output manager object. This method should
        take an action for the enabled plugins and their configuration. Usually,
        write the info to a file or print it somewhere.

        :param pluginsDict: A dict with all the plugin types and the enabled
                                plugins for that type of plugin.
        :param optionsDict: A dict with the options for every plugin.
        """
       pass
        
    def end(self):
        """
        This method is called when the scan has finished.
        """
        # Add the vulnerability results
	#
	all_vulns = kb.kb.get_all_vulns()
        all_infos = kb.kb.get_all_infos()
	vulns = itertools.chain(all_vulns, all_infos)
        #vulns = kb.kb.get_all_vulns()
        for i in vulns:
		vulnerability_element = self._asmfile.createElement("vulnerability")
		name_node = self._asmfile.createElement("name")
		name = self._asmfile.createTextNode(str(i.get_name()))
		name_node.appendChild(name)
		self.s_attack_type = "Other Application Attacks"
		if i.get_desc():
			for k in self._attack_type.keys():
				strDesc = str(i.get_desc())
				lindex = strDesc.find(str(k))
				lindex = lindex+1
				if lindex > 0:
					self.s_attack_type = self._attack_type[k]					
					break
		attack_type_node = self._asmfile.createElement("attack_type")
		attack_type = self._asmfile.createTextNode(self.s_attack_type)
		attack_type_node.appendChild(attack_type)
		if i.get_url():
			vurl = str(i.get_url())
			url_node = self._asmfile.createElement("url")
			url = self._asmfile.createTextNode(vurl)
			url_node.appendChild(url)
		if i.get_dc():
        		param = str(i.get_dc())
		else:
			param = " "

		parameter_node = self._asmfile.createElement("parameter")
		parameter = self._asmfile.createTextNode(param)
		parameter_node.appendChild(parameter)
		
		s = "low"
		if i.get_severity():
			s = str(i.get_severity())
		severity_node = self._asmfile.createElement("severity")
		severity = self._asmfile.createTextNode(s)
		severity_node.appendChild(severity)
		
		threat_node = self._asmfile.createElement("threat")
		threat = self._asmfile.createTextNode(s)
		threat_node.appendChild(threat)

		score_node = self._asmfile.createElement("score")
		score = self._asmfile.createTextNode("99")
		score_node.appendChild(score)

		status_node = self._asmfile.createElement("status")
		# Pending --
                status = self._asmfile.createTextNode("Pending")
                status_node.appendChild(status)

		opened_node = self._asmfile.createElement("opened")
                opened = self._asmfile.createTextNode("no")
                opened_node.appendChild(opened)

		if url_node:
			vulnerability_element.appendChild(attack_type_node)
			vulnerability_element.appendChild(name_node)
			vulnerability_element.appendChild(url_node)
			vulnerability_element.appendChild(parameter_node)
			vulnerability_element.appendChild(severity_node)
			vulnerability_element.appendChild(threat_node)
			vulnerability_element.appendChild(score_node)
			vulnerability_element.appendChild(status_node)
			vulnerability_element.appendChild(opened_node)
			self._topElement.appendChild(vulnerability_element)
        # Write xml report
        self._init()
	self._asmfile.appendChild(self._topElement)
        try:
		self._asmfile.writexml(self._file, addindent=" " * 4, newl="\n", encoding="UTF-8")
        	self._file.flush()

        finally:
            self._file.close()

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin writes the vulnerability messages to an F5 ASM XML import file.

        One configurable parameter exists:
            - output_file
        """

