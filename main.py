#!/usr/bin/env python
# Main
from client import ClientHandler, ShellHandler
from config import XmlParse, DeviceItem
from daemon import Daemon
from excepts import *
from static import *

# Various
import os, sys
from random import choice

# Input
from optparse import OptionParser, OptionGroup
import traceback
import locale
import getpass


class GoxCLI(object):
    def __init__(self):
        "Handles options and instanciate appropriate classes."
        self.opts, self.args = self.optSetup()
        self.xml = XmlParse(self.opts.xml)
        self.xml.read(self.opts.xml)
        self.opts.handshake = None

    def _interactive_device(self):
        devices = self.xml.devices
        devices = dict(enumerate(devices))
        print "{0} | {1} | {2} | {3}".format(
            "#".rjust(4), "Device".ljust(25), "CRY", "ID",
            )
        print " " + "-"*78
        for n,d in devices.iteritems():
            device = (str(n).rjust(4), d.name.ljust(25), d.standard, d.id)
            device = "{0} | {1} | {2} | {3}".format(*device)
            print device
        dNum = u""
        while not dNum.isdigit() or not devices.has_key(int(dNum)):
            dNum = raw_input("Device: ")
        return devices[int(dNum)]
    
    def optSetup(self):
        u"Set up optionsparser"
        usage = "Usage: %prog [options] action [arguments]"
        args  = sys.argv[1:]
        self.parser = OptionParser(add_help_option = False, usage = usage)
        self.parser.add_option(
            "-a", "--actions",
            action  = "store_true",
            dest    = "actions",
            default = False,
            help    = "List all avaiable actions and exit"
            )
        self.parser.add_option(
            "-b", "--in-btc",
            action  = "store_true",
            dest    = "asbtc",
            default = True,
            help    = "Specify amount in BTC (Standard)"
            )
        self.parser.add_option(
            "-c", "--currency",
            action  = "store",
            type    = "string",
            dest    = "currency",
            default = None,
            help    = "Specify currency"
            )
        self.parser.add_option(
            "-p", "--pretty-print",
            action  = "store_true",
            dest    = "pretty",
            default = False,
            help    = "Pretty-print result."
            )
        self.parser.add_option(
            "-d", "--daemon",
            action  = "store_true",
            dest    = "daemon",
            default = False,
            help    = "Start daemon."
            )
        self.parser.add_option(
            "-H", "--action-help",
            action  = "store",
            type    = "string",
            dest    = "action",
            default = None,
            help    = "Show the help of a specific action and exit"
            )
        self.parser.add_option(
            "-h", "--help",
            action  = "store_true",
            dest    = "help",
            default = False,
            help    = "Show this help message and exit"
            )
        self.parser.add_option(
            "-i", "--id",
            action  = "store",
            type    = "string",
            dest    = "id",
            default = None,
            help    = "Specify device with ID/Handshake"
            )
        self.parser.add_option(
            "-l", "--login",
            action  = "store_true",
            dest    = "login",
            default = None,
            help    = "Set daemon to listen for requests."
            )
        self.parser.add_option(
            "-k", "--kill-daemon",
            action  = "store_true",
            dest    = "kill",
            default = False,
            help    = "Kill running daemon."
            )
        self.parser.add_option(
            "-n", "--not-in-btc",
            action  = "store_false",
            dest    = "asbtc",
            default = True,
            help    = "Specify amount in currency."
            )
        self.parser.add_option(
            "-r", "--raw",
            action  = "store_true",
            dest    = "raw",
            default = False,
            help    = "Frontend-friendly output."
            )
        self.parser.add_option(
            "-x", "--xml",
            action  = "store",
            type    = "string",
            dest    = "xml",
            default = "goxcli.xml",
            help    = "Specify config-file"
            )
        return self.parser.parse_args()

    def _help(self, opt, args = []):
        appname = os.path.basename(sys.argv[0])
        if opt or args:
            # Option -h/--help
            if len(args) == 1:
                action = args[0].lower()
                try:
                    # Look for description in MtGoxAPI.
                    proc = getattr(self.api, action)
                except AttributeError:
                    # Action not found in MtGoxAPI, must be a custom function
                    #   with all info described in ClientHandler.
                    try:
                        proc  = getattr(self, "_action_{0}".format(action))
                    except AttributeError:
                        # Command not found, list commands instead.
                        self._proc_help(False)
                        return
                    else:
                        doc   = proc.__doc__.splitlines()
                        descr = doc.pop(0)
                else:
                    descr = proc.__doc__.splitlines().pop(0)
                    proc  = getattr(self, "_action_{0}".format(action))
                    doc   = proc.__doc__.splitlines()
                hargs = doc
                help  = descr
                while help:
                    line,sep,tail = help[:68].rpartition(" ")
                    help = help[len(line+sep):] if len(help) > 68 else False
                    if help:
                        print line
                    else:
                        print "\n%s %s\n" % (line,tail)
                action,n,arguments = hargs.pop(0).partition(" ")
                usage = (appname, action, arguments)
                usage = "Usage: %s [options] %s %s\n" % usage
                if len(hargs):
                    "List of arguments avaiable for %s\n" % action
                    for line in hargs:
                        example,n,descr = line.partition(" ")
                        print example
                        while descr:
                            line,sep,tail = descr[:68].rpartition(" ")
                            descr = descr[len(line+sep):] if len(descr) > 68 else False
                            if descr:
                                print "{:<2}".format("") + line
                            else:
                                print "  %s %s\n" % (line,tail)
                    print "Note: <Arguments> is required while" + \
                          " [arguments] is optional\n"
                while usage:
                    line,sep,tail = usage[:68].rpartition(" ")
                    usage = usage[len(line+sep):] if len(usage) > 68 else False
                    if usage:
                        t = "\\"
                        print line, t
                    else:
                        print "%s %s" % (line,tail)
            else:
                self.parser.print_help()
                print "\nNOTE: If you want to send a request from" + \
                      " commandline while using a\n    encrypted secret you" + \
                      " may need to have a daemon or shell running\n"
        else:
            # Option -a/--actions
            print u"Detailed usage: %s -h action\n" % appname
            print u"Actions marked [*] requires authentication with Mt.Gox.\n"
            header = list()
            header += [u"{:<12}".format("Action")]
            header += [u"{:<22}".format("Arguments")]
            header += [u"{:<32}".format("Description")]
            header += [u"A\n"]
            print "".join(header)
            for action,args,descr,auth in (
                (u"activate",u"<activationkey>",u"Activate application",False),
                (u"block",u"[hash=\"\"] [depth=...",u"Get trade(s)",False),
                (u"btcaddress",u"[hash=\"\"]",u"Get address-information",False),
                (u"buy",u"<amount> [price]",u"Buy BTC at [price]",True),
                (u"cancel",u"<type> <oid>",u"Cancel order",True),
                (u"delete",u"<id> [id] [id] [i...",u"Delete device(s)",False),
                (u"deposit",u"",u"Get address for BTC-deposits",True),
                (u"depth",u"[side=\"\"] [steps]...",u"Get depth-table",False),
                (u"devices",u"",u"List devices in config",False),
                (u"history",u"",u"Get wallet history",True),
                (u"info",u"",u"Get full private info",True),
                (u"lag",u"",u"Process-time at Mt.Gox",False),
                (u"orders",u"<\"type\">",u"Get list of open orders",True),
                (u"sell",u"<amount> [price]",u"Sell BTC at [price]",True),
                (u"ticker",u"",u"Get current ticker",False),
                (u"trades",u"[since=0]",u"Get trade(s)",False),
                (u"withdraw",u"<amount> [btc=15B...",u"Withdraw funds",True)
                ): print "{:<12}".format(action) + "{:<22}".format(args) + \
                         "{:<31}".format(descr) + {True:"[*]",False:"[ ]"}[auth]

    def run(self):
        device = None
        if self.opts.id:
            if self.opts.id[0] == "h":
                self.opts.handshake, self.opts.id = self.opts.id, False
            else:
                device = self.xml.getDevice(self.opts.id)
                if not device:
                    raise InputError("Invalid id")
        if self.opts.help or self.opts.actions:
            self._help(self.opts.help, self.args)
        else:
            if self.args:
                # Pass action to minimal client
                self.cmd = ClientHandler(self.opts, self.xml, device)
                result   = self.cmd.action(self.opts, self.args)
            else:
                try:
                    # Check options that's interactive
                    if self.opts.kill:
                        # Kill main daemon
                        result = DaemonIPC.send(r'{"action": "Terminate"}')
                    elif self.opts.daemon:
                        # Start daemon
                        result = Daemon(self.xml).run()
                    elif self.opts.login:
                        # Login device at daemon
                        result = self.subscribe()
                    else:
                        result = None
                except (MtGoxError, DaemonError), e:
                    result = r'{"result": "error", "error": "%s"}' % e.message
            if not result:
                # Start Shell-like client
                locale.setlocale(locale.LC_ALL, "")
                client = ShellHandler(self.opts, self.xml, device)
                client.run(locale.getpreferredencoding())
            else:
                # Print results
                if self.opts.raw:
                    sys.stdout.write(result)
                elif self.opts.pretty:
                    result = JsonParser.parse(result, force = True)
                    print json.dumps(result, sort_keys = False, indent = 4)
                else:
                    print result

    def subscribe(self, id=None, pw=None):
        if not id: id = self._interactive_device().id
        while not pw:
            pw = getpass.getpass("Password: ")
        json = {
            "action" : "login",
            "id"     : id,
            "pw"     : pw
            }
        # reply = { "result" = "success", "return" = "handshake" }
        result = DaemonIPC.send( JsonParser.build(json) )
        return JsonParser.build(result)

    def cmd(self, device):
        try:
            return self.cmd.action(self.args)
        except (InputError, MtGoxError, DaemonError, CredentialError), e:
            return JsonParser.build({
                u"result": u"error",
                u"error": e.message
                })
        except urllib2.HTTPError, e:
            return JsonParser.build({
                u"result": u"error",
                u"error": u"HTTPError %s" % e.code
                })


def main():
    GoxCLI().run()

if __name__ == "__main__":
    main()
