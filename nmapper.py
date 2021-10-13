#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import cmd
import os
import signal
import sys
from pathlib import Path
#from lib import *
from terminaltables import AsciiTable

intro = '''\033[1m\033[91m     
      ::::    :::  :::   :::      :::    ::::::::: ::::::::: ::::::::::::::::::: 
     :+:+:   :+: :+:+: :+:+:   :+: :+:  :+:    :+::+:    :+::+:       :+:    :+: 
    :+:+:+  +:++:+ +:+:+ +:+ +:+   +:+ +:+    +:++:+    +:++:+       +:+    +:+  
   +#+ +:+ +#++#+  +:+  +#++#++:++#++:+#++:++#+ +#++:++#+ +#++:++#  +#++:++#:    
  +#+  +#+#+#+#+       +#++#+     +#++#+       +#+       +#+       +#+    +#+    
 #+#   #+#+##+#       #+##+#     #+##+#       #+#       #+#       #+#    #+#     
###    #######       ######     ######       ###       #############    ###      


\033[0m
            Version    : 1.0
            Author     : Orhan YILDIRIM
            Medium     : @orhan_yildirim
            Linkedin   : www.linkedin.com/in/orhan-yildirim
            Note       : Who's up!

 \033[1m\033[94m[*]\033[0m You can use "help" command for access help section\033[0m.
'''

def ctrlcHandler(signum, frame):
    print(" \n\n \033[1m\033[94m[*]\033[0m I hope you enjoyed!\033[0m\n")
    sys.exit(0)

class sfCmd(cmd.Cmd):
    global helpText
    helpText = "Commands"
    def __init__(self, intro=intro, prompt="\033[1mnMapper> \033[0m"):
        cmd.Cmd.__init__(self)
        self.intro = intro
        self.prompt = prompt
        self.doc_header = helpText
        global moduleName
        moduleName = ""

    def do_list(self, line):
        optionsValues = [
            ["ID", "Module", "Description"],
            ["1", "Host Discovery", "test"],
            ["2", "SMB Share Unpriviliged", "test"],
            ["3", "SMB Share Privileged", "test"],
            ["4", "SMB Signing False", "test"],
            ["5", "SMB Vulnerabilities", "test"],
            ["6", "SMB Vulnerabilities", "test"],
            ["7", "SMB Vulnerabilities", "test"],
            ["8", "SMB Vulnerabilities", "test"],
            ["9", "SMB Vulnerabilities", "test"],
            ["10", "SMB Vulnerabilities", "test"]
        ]
        optTable = AsciiTable(optionsValues)
        optTable.outer_border = False
        optTable.inner_column_border = True
        print("\n" + optTable.table + "\n")

    def do_use(self, line):
        try:
            global moduleName
            moduleName = line.split()[0]
        except IndexError:
            print("\n \033[1m\033[91m[!]\033[0m You need to give a valid module id.\033[0m\n")
        if moduleName in ("1", "Host Discovery"):
            moduleName = "Host Discovery"
            sfCmds = def_hostDiscovery()
            sfCmds.cmdloop()
        elif moduleName in ("2", "test..."):
            moduleName = "test..."
            sfCmds = mpPSModule()
            sfCmds.cmdloop()
        elif moduleName in ("3", "test..."):
            moduleName = "test..."
            sfCmds = jsHtaModule()
            sfCmds.cmdloop()
        elif moduleName in ("4", "test..."):
            moduleName = "test..."
            sfCmds = vbaModule()
            sfCmds.cmdloop()
        else:
            pass

    def do_exit(self, line):
        print(" \n \033[1m\033[94m[*]\033[0m I hope you enjoyed!\033[0m\n")
        return True

    def emptyline(self):
        pass

    def help_list(self):
        print("List available modules")

    def help_use(self):
        print("Use specific module. Syntax: use <id> ")

    def help_exit(self):
        print("Exit nMapper")

    def help_info(self):
        print("Show modules options and parameter values")

    def help_set(self):
        print("Set value to parameter. Syntax: set <parameter> <value>")

    def help_run(self):
        print("Run the module with current values.")

    def help_back(self):
        print("Back to nMapper main menu.")

class def_hostDiscovery(sfCmd):
    global m_rhost
    m_rhost = None

    def __init__(self):
        sfCmd.__init__(
            self, intro="", prompt="\033[1mnMapper [\033[91m" + moduleName + "\033[0m\033[1m] >\033[0m ")

    def do_info(self, line):
        print("\n \033[1m\033[94m[*]\033[0m Module Info\033[0m\n")
        print(''' This module can be used to host discovery. It uses "nmap" "-T5" option for scanning to target files up top 100 ports.''')
        print("\n \033[1m\033[94m[*]\033[0m Module Options\033[0m")
        optionsValues = [
            ["Parameter", "Required", "Value", "Description"],
            ["RHOST", "Yes", m_rhost, "Setting for target(s). Accepted: CIDR formats or a txt file."]

        ]
        optTable = AsciiTable(optionsValues)
        optTable.outer_border = False
        optTable.inner_column_border = False
        optTable.justify_columns[1] = "center"
        print("\n" + optTable.table + "\n")

    def do_set(self, line):
        global m_rhost
        if line.split()[0] == "RHOST":
            m_rhost = line.split()[1]
            print("RHOST => " + line.split()[1])
               
        else:
            print("\n \033[1m\033[91m[!]\033[0m Please enter valid value.\n")


    def do_run(self, line):
        filename = Path("/root/targets.txt")
        print(filename.name)
        print(filename.read_text())
        if not filename.exists():
            print("Oops, file doesn't exist!")
        else:
            pass
        cmd=('mkdir nmapper ;')
        print('Started host discovery process... ')
        cmd+= ('nmap -iL {} -T5 -oG - | grep "Status: Up" | cut -d " " -f 2 > nmapper/host_discovery.txt  ;'.format(filename))
        os.system(cmd)
            
    def do_back(self, line):
        return True

    def do_exit(self, line):
        pass






if __name__ == '__main__':
    signal.signal(signal.SIGINT, ctrlcHandler)
    sfCmds = sfCmd()
    sfCmds.cmdloop()


'''
        
        cmd=('mkdir nmapper ;')
        print('Killing "msfrcpd" process... ')
        #cmd+= ('nmap -iL {} -T5 -oG - | grep "Status: Up" | cut -d " " -f 2 > nmapper/host_discovery.txt  ;'.format(m_rhost))
        cmd+=("ps -ef | grep msfrpcd | grep -v grep | awk '{print $2}' | xargs kill > /dev/null 2&>1 ;")
        print('Restarting "msfdb" process... ')
        cmd+=("msfdb stop ; ")
        cmd+=("msfdb start ;")
        cmd+=('msfrpcd -P tmppassword -S -a 127.0.0.1 > /dev/null 2&>1')
        print('Started "msfrpcd" process... ')
        os.system(cmd)
        '''