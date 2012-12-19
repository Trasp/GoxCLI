#!/usr/bin/env python
# Clienthandler
from static import *
from api import MtGoxAPI
from daemon import Daemon

from parsers import *

# Various
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import partial
from random import choice
import string, time

# Input
import getpass
import readline
import traceback


class ClientHandler(object):
    u"Handles arguments and additionally calls appropriate request and" \
    u"parser of result."
    def __init__(self, opts, xml, device = None):
        self.xml         = xml
        self.api         = MtGoxAPI(self.xml, lambda: self.credentials)
        self.opts        = opts
        self.device      = device
        self.user        = None
        self._standard   = None
        self._key        = None
        self._secret     = None
        self._counter    = 0
        self._handshakes = dict()

    @property
    def credentials(self):
        if not all((self._key, self._secret)):
            device = self.device
            if not device:
                if self.opts.id:
                    device = self.xml.getDevice(self.opts.id)
                else:
                    devices = self.xml.devices
                    try:
                        device, = devices
                    except ValueError, e:
                        if e.message == "too many values to unpack":
                            # More than one device found in config.
                            raise CredentialError(u"No device specified.")
                        else:
                            raise CredentialError(
                                u"No device found in config, you must activate your" + \
                                u"application to use this function.")
                if not device or device.length:
                    raise CredentialError(u"Not logged in.")
                self.device = device
            self._key, self._secret = device.key, device.secret
        self._counter += 1
        return self._key, self._secret, self._counter

    @credentials.setter
    def credentials(self, values):
        u"Set all variables needed and test them."
        device, secret    = values
        self.device       = device
        self._key         = device.key
        self._standard    = device.standard
        self._secret      = secret
        self._counter     = 0
        self._handshakes  = dict()
        self.api.standard = device.standard
        try:
            json = JsonParser.parse(self.api.info())
        except ParseError, e:
            self.user      = None
            self.device    = None
            self._standard = None
            self._key      = None
            self._secret   = None
            self._counter  = 0
            raise e
        else:
            self.user   = json["return"]["Login"]

    @property
    def device(self):
        if self._device:
            return self._device
        elif self.opts.id:
            device = self.xml.getDevice(self.opts.id)
            if not self.xml.getDevice(self.opts.id):
                raise InputError("Invalid id")
        else:
            try:
                device, = self.xml.devices
            except ValueError:
                device = None
                #if e.message == "too many values to unpack":
                #    device = None
                #else:
                #    raise InputError("Invalid XML: No device found",
                #                      kind = "XML", arg = "No device found")
            else:
                if device.length and not self._handshakes.has_key(device.id):
                    device = None
        return device

    @device.setter
    def device(self, device):
        self._device = device

    @property
    def dName(self):
        if self.device:
            return self.device.name
        else:
            return None

    @property
    def standard(self):
        u"Returns standard-currency for current device"
        if not self._standard:
            if not self.device:
                if not self.xml.cfg:
                    self.xml.read()
                if self.opts.id:
                    self.device = self.xml.getDevice(self.opts.id)
                else:
                    # Take first device in config, but only if it's the only one
                    n = 0
                    for d in self.xml.iterDevices():
                        if n:
                            break
                        n += 1
                    else:
                        if n:
                            self.device = d
                    if not self.device:
                        self._standard = "USD"
                        return self._standard
            self._standard = self.device.standard
        return self._standard

    @property
    def handshake(self):
        return self.opts.handshake if self.xml.handshakes else self.device.id

    def __cmd_name(self, attr, exp):
        match = re.match(exp, attr)
        return match.group(1) if match != None else None

    def _get_cmds(self, exp):
        u"Takes all attributes in self and match them against exp," \
        u" remove duplicates and returns a sorted generator-object" \
        u" containing valid commands."
        return sorted(
            set(
                filter(
                    lambda cmd:
                        cmd != None,
                        (self.__cmd_name(attr,exp) for attr in dir(self))
                )
            )
        )

    def _action_block(self, opts, args):
        u"block <[hash=str]/[number=int]>\n"
        u"[hash=str] Get information within block with the specified hash.\n" \
        u"[depth=int] Get information within block by specifying depth."
        hash, depth = None, None
        if len(args):
            for arg in args:
                # Split key-word arguments
                try:
                    key,value = arg.split("=")
                    key = key.lower()
                except ValueError:
                    raise InputError("Invalid argument: " + arg, arg=arg)
                else:
                    # Parse key-word arguments
                    if key == "depth":
                        try:
                            depth = int(value)
                        except ValueError:
                            raise InputError("Invalid value: " + value, kind="value", arg=value)
                    # Parse key-word arguments
                    elif key == "hash":
                        hash = value
                    else:
                        raise InputError("Invalid argument: " + key, arg=key)
        else:
            raise InputError("Not enough arguments.")
        return {"hash":hash, "depth":depth}

    def _action_btcaddress(self, opts, args):
        u"btcaddress <address>\n" \
        u"<address> The address to look up, not formatted as normal addresses" \
        u" and have not been able to recieve any information on the subject" \
        u" from Mt.Gox who otherwise has been really helpful. If you find out" \
        u" how to format these addresses, please send me an e-mail."
        if not len(args):
            raise InputError("Not enough arguments.")
        return {"hash": args[0]}

    def _action_buy(self, opts, args):
        u"Post bid-order at Mt.Gox, buying bitcoins.\n" \
        u"buy <amount> [price]\n" \
        u"<amount> Amount of BTC to buy. Prefix or suffix with currency" \
                u" symbol to specify amount in currency instead of BTC.\n" \
        u"[price] Specify at what price you want to request your order.\n" \
        u"NOTE: If you don't enter a price, GoxCLI will fetch the OrderBook," \
             u" trying to put up a properly sized ask, I haven't even checked" \
             u" if these orders are exact under normal circumstances, as" \
             u" everything else in this application YOU USE THIS AT YOUR OWN " \
             u" RISK "
        return self._addorder(opts, args, "bid")

    def _action_sell(self, opts, args):
        u"Post ask-order at Mt.Gox, selling bitcoins.\n" \
        u"sell <amount> <price>\n" \
        u"<amount> Amount of BTC to sell. Prefix or suffix with currency" \
                u" symbol to specify amount in currency instead of BTC.\n" \
        u"<price> Specify at what price you want to request your order."
        u"NOTE: If you don't enter a price, GoxCLI will fetch the OrderBook," \
             u" trying to put up a properly sized bid, I haven't even checked" \
             u" if these orders are exact under normal circumstances, as" \
             u" everything else in this application YOU USE THIS AT YOUR OWN " \
             u" RISK "
        return self._addorder(opts, args, "ask")

    def _addorder(self, opts, args, kind):
        u"Internal function to generate orders to put at Mt.Gox called by" \
        u" sell- and buy-action."
        currency = opts.currency.upper() if opts.currency else self.standard
        decimals = self.xml.currency(currency)[0]
        bPrec = Decimal("0.00000001")
        cPrec = Decimal(Decimal(1) / 10 ** decimals)
        if args:
            try:
                amount,price = args if len(args) > 1 else (args[0],None)
            except ValueError:
                raise InputError("Expected 1 or 2 arguments, got %s" % len(args))
            else:
                amount = Decimal(amount)
        else:
            raise InputError("Expected 1 or 2 arguments, got %s" % len(args))
        if price:
            price = Decimal(price)
            # Create order with specified price and amount
            if not opts.asbtc:
                # Convert amount to BTC
                amount = amount / price
            # Convert amount and price to int
            amount = amount / bPrec
            price  = price / cPrec
        else:
            # Generate order with a certain amount or value
            side   = "bids" if kind == "ask" else "asks"
            json   = self.request("depth", currency=currency)
            kwargs = {"currency": currency}
            if opts.asbtc:
                # Convert amount to to int
                amount = amount / bPrec
                # Get price
                pargs = {"steps": 1, "amount": amount, "side": side}
                args  = ("depth", json, kwargs, self.xml, pargs)
                json  = JsonParser.process(*args, raw = False )
                price = int(json["return"][side][0]["price_int"])
            else:
                # Amount given in currency-value.
                pargs = {"value": amount, "iv": True, "side": side}
                # Convert value to to int
                total = amount / cPrec
                total = total  / bPrec
                # Get price and amount
                args    = ("depth", json, kwargs, self.xml, pargs)
                orders  = JsonParser.process(*args, raw = False )
                orders  = orders["return"][side]
                current = 0
                amount  = 0
                order   = orders.pop(0)
                while orders:
                    # Count amount of all orders up to the last one.
                    current += int( order["value_int"] )
                    amount  += int( order["amount_int"] )
                    order    = orders.pop(0)
                else:
                    # Take price and the rest of the amount that's needed.
                    rest   = total - current
                    price  = int( order["price_int"] )
                    amount = current + ( rest / price )
        return {"amount":str(amount), "price":str(price), "currency":currency}

    def _action_cancel(self, opts, args):
        u"cancel <type> <oid>\n" \
        u"<type> Order type, could be either ask or bid.\n" \
        u"<oid/all> OrderID of the order."
        if len(args) != 2:
            raise InputError("Expected 2 arguments, got %s" % len(args))
        else:
            if args[0] not in ("bid","ask"):
                raise InputError("Invalid argument: %s" % args[0], arg=args[0])
            else:
                return { "kind":args[0], "oid": args[1] }
        
    def _action_delete(self, opts, args):
        u"Delete device saved in config.\n" \
        u"delete <id> [id] [id] [...]\n" \
        u"<id> Device's id\n" \
        u"NOTE: You still have to revoke your key at MtGox.com!"
        returns = []
        if not args:
            raise InputError("Expected at least 1 argument, got %s" % len(args))
        for id in args:
            if self.xml.delDevice(id, write = False):
                returns.append(id)
        else:
            self.xml.write()
            json = { "result": "success",
                     "return": returns }
        return JsonParser.build(json)

    def _action_devices(self, opts, args):
        u"List devices saved in config.\n" \
        u"devices"
        returns = []
        for device in self.xml.devices:
            returns.append({
                "id"       : device.id,
                "name"     : device.name,
                "standard" : device.standard,
                "encrypted": "True" if int(device.length) else "False",
                "listening": "True" if int(device.listening) else "False"
                })
        else:
            self.xml.write()
            json = { "result": "success",
                     "return": returns }
        return JsonParser.build(json)

    def _action_deposit(self, opts, args):
        u"deposit"
        return dict()

    def _action_depth(self, opts, args):
        u"depth [side=str] [steps=int] [low=dec] [high=dec] [amount=dec]" \
                u" [value=dec] [iv=bool] [cumulate=bool] [full=bool]\n" \
        u"[side=str] Only parse one side of table, i.e. bids or asks.\n" \
        u"[steps=int] Only return <int> amount of orders on each side. If" \
                u" other filters is applied who returns more orders they are" \
                u" cumulated to <int> orders.\n" \
        u"[low=dec] Lets you chose a pricerange and only returns orders that" \
                u" has a price set below <dec>\n" \
        u"[high=dec] Lets you chose a pricerange and only returns orders that" \
                u" has a price set above <dec>\n" \
        u"[amount=dec] Returns orders up to and including the order where sum" \
                u" of that and previous orders amount's are equal or more than"\
                u" <dec>\n" \
        u"[value=dec] Returns orders up to and including the order where sum" \
                u" of that and previous orders value's are equal or more than" \
                u" <dec>\n" \
        u"[iv=bool] Add value-parameters to all orders, representing value of" \
                u" each order's amount in currency.\n"\
        u"[cumulate=bool] Cumulates amounts, i.e. all orders show total" \
                u" amount of previous orders and current.\n" \
        u"[full=bool] Requests full depth-table from Mt.Gox, otherwise only a" \
                u" limited table around the current price is returned which is" \
                u" much faster to recieve and process."
        currency = opts.currency.upper() if opts.currency else self.standard
        # Setup DepthParser with args
        full = False
        if args:
            if len(args) == 1 and args[0].lower() == "full=true":
                kwargs = None
                full = True
            else:
                kwargs = {}
                try:
                    for arg in args:
                        key,value = arg.split("=")
                        if key == "full":
                            full = value
                        else:
                            kwargs[key] = value
                except ValueError:
                    raise InputError("Invalid argument: %s" % arg, arg=arg)
        else:
            kwargs = None
        return {"currency": currency, "full": full, "parse": kwargs}

    def _action_history(self, opts, args):
        u"history"
        currency = opts.currency.upper() if opts.currency else self.standard
        if args:
            try:
                page = int(args[0])
            except ValueError:
                raise InputError("Invalid argument: %s" % args[0], arg=args[0])
        else:
            page = 1
        return { "currency": currency, "page": page }

    def _action_info(self, opts, args):
        u"info"
        return dict()

    def _action_lag(self, opts, args):
        u"lag"
        return dict()

    def _action_orders(self, opts, args):
        u"orders"
        return dict()

    def _action_status(self, opts, args):
        u"status <type> <oid>\n" \
        u"<type> Order type, could be either ask or bid.\n" \
        u"<oid> OrderID of the order."
        if len(args) == 2:
            kind,oid = args
        else:
            raise InputError("Expected 2 argument, got %s" % len(args))
        return { "kind": kind, "oid": oid }
        
    def _action_ticker(self, opts, args):
        u"ticker"
        currency = opts.currency.upper() if opts.currency else self.standard
        return { "currency": currency }

    def _action_trades(self, opts, args):
        u"trades [time=int] [since=int]\n" \
        u"[time=int] Returns all trades that happend since <int> number of " \
                u" seconds ago.\n"\
        u"[since=int] Returns trades made after trade with TradeID <int>.\n"
        currency = opts.currency.upper() if opts.currency else self.standard
        since = None
        if len(args) > 1:
            raise InputError("Expected 0 or 1 arguments, got %s" % len(args))
        elif args:
            arg = args[0]
            # Split key-word argument
            try:
                key,value = arg.split("=")
                key = key.lower()
            except ValueError:
                raise InputError("Invalid argument: " + arg, arg=arg)
            else:
                # Parse key-word argument
                try:
                    if key == "since":
                        since = int(value)
                    elif key == "time":
                        since = int(time.time()*1E6 - int(int(value)*1E6))
                    else:
                        raise InputError("Invalid argument: " + arg, arg=arg)
                except ValueError:
                    raise InputError("Invalid value: %s" % v,
                                     kind = "value", arg  = v)
        return { "currency": currency, "since": since }

    def _action_transaction(self, opts, args):
        u"transaction <hash=str>\n" \
        u"<hash=str> Hash of the transaction you want to request information" \
        u" about."
        if len(args) == 1:
            return { "hash": args[0] }
        else:
            raise InputError("Expected 1 argument, got %s" % len(args))
        
    def _action_withdraw(self, opts, args):
        u"withdraw <currency> <destination=str> <amount=dec> <account=str>\n" \
        u"<currency> Currency as three letter code or BTC (Currently only \n" \
        u" coupons works with other currencies than BTC and USD).\n" \
        u"<destination=str> Method of withdrawal, can be any of BTC, coupon" \
        u" Dwolla, LR (Liberty Reserve) and Paxum.\n" \
        u"<amount=dec> Amount to withdraw\n" \
        u"<account=str> Your BTC-address, Dwolla-account, LR-account or" \
        u" Paxum-account\n" \
        u"<green=bool> Use the \"green address\"-feature."
        if len(args) < 3:
            raise InputError("Expected 3,4 or 5 arguments, got %s" % len(args))
        elif len(args) > 5:
            raise InputError("Expected 3,4 or 5 arguments, got %s" % len(args))
        currency = args.pop(0)
        if currency.upper() != "BTC":
            try:
                self.xml.currency(currency)
            except KeyError:
                raise InputError("Invalid argument: %s", arg = currency)
        account = None
        for arg in args:
            try:
                k,v = arg.split("=")
                k = k.lower()
            except ValueError:
                raise InputError("Invalid argument: " + arg, arg=arg)
            else:
                if k == "destination":
                    if v.lower() in ("btc","dwolla","lr","paxum", "coupon"):
                        destination = v
                elif k == "amount":
                    amount = Decimal(v)
                elif k == "account":
                    account = str(v)
                elif k == "green":
                    if v.lower() in ("true","false"):
                        green = True if v.lower() == "true" else False
                    else:
                        raise InputError("Invalid value: %s" % v,
                                         kind="value", arg=v)
                else:
                    raise InputError("Invalid argument: %s" % k, arg=k)
        try:
            if destination != "coupon" and account == None:
                raise UnboundLocalError
        except UnboundLocalError:
            raise InputError("Missing argument.")
        else:
            return { "currency":    currency.upper(),
                     "destination": destination,
                     "amount":      amount,
                     "account":     account }
    
    def prompt(self, prompt, default):
        y = ("y","yes","") if default else ("y","yes")
        a = None
        while a not in ("n","no","y","yes",""):
            a = raw_input("%s [Y/n]: " % prompt).lower()
        if a in y:
            return True
        else:
            return False

    def _action_activate(self, opts, args):
        u"activate <activation-key>\n"\
        u"<activation-key> This key is retrieved from Security Center at" \
                        u" Mt.Gox under the tab \"Application Access\".\n" \
        u"NOTE: You can run this more than once to use multiple devices."
        pw = str()
        if not len(args) == 1:
            if not len(args):
                raise InputError("Missing key for activation, you can get one in"\
                                 "security center at MtGox.com")
            else:
                raise InputError("Expected 1 argument, got %s" % len(args))
        # Retrieve devicename
        devices = self.xml.devices
        if devices and len(devices) == 1:
            dName = devices[0].name
        else:
            # Assign prefix + random string
            dName = "GoxCLI_"
            dName += "".join(choice(string.ascii_uppercase + string.digits) for x in range(10))
        # Get user inputs
        pw, dName = self._interactive_activate(dName=dName)
        return dict(key=args[0], name=dName, pw=pw)

    def _interactive_activate(self, dName = None):
        u"Take user input needed for interactive activation from CLI"
        pw = None
        if not self.prompt("Use devicename %s?" % dName,True):
            # User chose to input new devicename
            dName = raw_input("Use devicename: ").lower()
        # Disclaim about encoded secret
        print "\nYou can choose two different methods for saving secret in" + \
              " config.\n\n" + \
              "1. Encryption. More secure but requires but requires" + \
              " interactive login.\n" + \
              "2. Encoding. NOT SECURE, allows use of commands without" + \
              " logging in."
        # Ask whether to encrypt secret or not
        if self.prompt("Encrypt secret?",True):
            print u"Enter password for secret encryption."
            while not pw:
                # Prompt user to provide password to encrypt secret
                p1 = getpass.getpass("Password: ").decode('string_escape')
                p2 = getpass.getpass("Repeat: ").decode('string_escape')
                if p1 == p2:
                    pw = p1
                else:
                    print u"Passwords don't match, try again."
        if len(self.xml.devices) == 1:
            print "\nOne device allready in config."
            if self.prompt("Overwrite?",True):
                self.xml.devices = []
        return pw, dName

    def action(self, opts, args):
        u"Take first argument and launch appropriate function"
        # Get action
        try:
            action = args.pop(0).lower()
        except IndexError:
            raise InputError("Input did not contain any action",
                             kind="action", arg=None)
        # Get local function
        try:
            proc = getattr(self, "_action_{0}".format(action))
        except CredentialError, e:
            return JsonParser.build(dict(error=e))
        except AttributeError,e:
            raise InputError("Invalid action: %s" % action,
                             kind = "action", arg = action)
        except (decimal.InvalidOperation, InvalidOperation), e:
            v = e.message.rpartition(" ")[2].lstrip("u\'").rstrip("'")
            raise InputError("Invalid value: %s " % v, kind="value", arg=v)
        else:
            # Do API-request
            return self.request( action, proc(opts, args) )

    def request(self, action, kwargs={}):
        try:
            # Try requesting action from listening daemon
            if self.handshake:
                kwargs["handshake"] = self.handshake
            json = self.requestDaemon(action = action, **kwargs)
        except DaemonError, e:
            if self.handshake:
                del kwargs["handshake"]
            json = self.requestHTTP(action = action, **kwargs)
        else:
            if json == r'{"result": "error", "error":"Not logged in."}':
                json = self.requestHTTP(action = action, **kwargs)
        return json

    def requestDaemon(self, **kwargs):
        json = JsonParser.build(kwargs)
        return DaemonIPC.send(json)
        
    def requestHTTP(self, action, **kwargs):
        parse  = kwargs.pop("parse", None)
        result = self.api.request(action, **kwargs)
        if parse or action == "activate":
            result = JsonParser.process(action, result, kwargs, self.xml, parse)
        return result


class ShellHandler(ClientHandler):
    @property
    def handshake(self):
        device = self.device
        if device:
            if self.xml.handshakes:
                handshake = self._handshakes.get( device.id, None )
            else:
                handshake = device.id
        else:
            handshake = None
        return handshake

    def __complete(self, text, state):
        raw  = r"^_shell_(?:read_)?(?:{0})(.+)$".format(text)
        exp  = re.compile(raw)
        cmds = self._get_cmds(exp)
        try:
            cmd = text + self._get_cmds(exp)[state]
        except IndexError:
            return None
        else:
            return cmd + (" " if len(cmds) == 1 else "")

    def __help_format_line(self, line, length, spacing, rJust = False):
        u"Formats lines with spacing and fixed length."
        if rJust:
            # rJust = RightAdjust, args = Length/Spaces to be added after RAdjust.
            arg,s,line = line.partition(" ")
            if len(arg) <= rJust:
                length  -= rJust
                spacing += rJust
                rJust    = rJust-len(arg)
            else:
                length  -= len(arg)
                spacing += len(arg)
                rJust    = 0
        else:
            rJust = 0
            arg   = str()
            length = length - spacing
        spacing = " " * spacing
        # Take all words that can fit into a 79 character long string.
        pLine,sep,tail = line[:length].rpartition(" ")
        # Remove words from variable or set to false if no words remains.
        line = line[len( pLine + sep ):] if len(line) > length else False
        if (line == False and pLine != tail):
            pLine = "".join( (pLine, sep, tail) ) 
        out = (" " * rJust, arg)
        yield "".join(out), pLine
        while line:
            # Take more words and print with added spacing.
            pLine, sep, tail = line[:length].rpartition(" ")
            # Remove words from variable or set to false if no words remains.
            line = line[ len(pLine + sep) :] if len(line) > length else False
            if (line == False and pLine != tail):
                pLine = "".join( (pLine, sep, tail) )
            yield spacing, pLine
    
    def __parse_tokens(self, tokens):
        u"Parse lines from __tokenize_command and return as tuple."
        cmd  = None
        args = []
        for token in tokens:                
            if token.decode("utf-8") == u";":
                if cmd:
                    yield (cmd, args)
                    cmd  = None
                    args = []
            elif not cmd:
                cmd = token
            else:
                args.append(token)
        if cmd:
            yield (cmd, args)

    def __tokenize_command(self, line):
        u"Split command-line into multiple commands if necessary."
        remaining = line
        while remaining:
            found = False
            for (pattern, sub) in self.__token_types:
                match = pattern.match(remaining)
                if match:
                    raw_token = match.group(0)
                    assert len(raw_token) > 0, u"empty token"
                    token     = sub(raw_token)
                    if token is not None: yield token
                    remaining  = remaining[len(raw_token):]
                    found      = True
                    break
            if not found:
                message = "\n".join(
                    u"  {0}^".format(u" " * (len(line) - len(remaining)),
                    u"Syntax error."))
                raise TokenizationError(message)

    def _error(self, message, *rest):
        u"Prints errormessages in neat colors."
        args    = u" ".join(rest) if rest else u""
        message = self.colorText(message or u'', "error_message")
        args    = self.colorText(args    or u'', "error_arg")
        print u"{message} {args}".format( message = message, args = args )

    def _interactive_activate(self, dName=None):
        u"Take user input needed for interactive activation, with ansicolors."
        answer = None
        pw     = None
        while answer not in ("y","yes","n","no",""):
            out    = "\nUse devicename %s? [Y/n]: " % dName
            answer = raw_input( self.colorText(out, "shell_self") ).lower()
        else:
            if answer.lower() not in ("y","yes",""):
                # User chose to input new devicename
                out   = self.colorText("Use devicename: ","shell_self")
                dName = raw_input(out)
            # Disclaim about encoded secret
            m = u"\nYou must choose method for saving your secret in config.\n"
            m += "1. Encryption.\n2. Encoding.\n\n"
            m += "If you enable encryption your secret will be kept "  + \
                     " encrypted with AES-256, if not it will be saved"    + \
                     " encoded which IS NOT SECURE, but will allow use of" + \
                     " commands without logging in or using a Daemon."
            print self.colorText(out, "shell_self")
            # Ask whether to encrypt secret or not
            answer = None
            while answer not in ("y","yes","n","no",""):
                out    = self.colorText("\nEncrypt secret? [Y/n]: ","shell_self")
                answer = raw_input(out).lower()
            else:
                if answer.lower() in ("y","yes",""):
                    # User chose encrypted
                    encrypted = True
                    out = u"\nEnter password for secret encryption."
                    print self.colorText(out, "shell_self")
                    while not pw:
                        # Prompt user to provide password to encrypt secret
                        out = self.colorText("Password: ","shell_self")
                        p1  = getpass.getpass(out).decode('string_escape')
                        out = self.colorText("Repeat: ","shell_self")
                        p2  = getpass.getpass(out).decode('string_escape')
                        if p1 == p2:
                            pw = p1
                        else:
                            out = u"Passwords didn't match, try again."
                            print self.colorText(out, "shell_self")
        return pw, dName
        
    def _interactive_device(self):
        u"Prompt user to choose device in config, nicely colored."
        devices = self.xml.devices
        if devices:
            try:
                device, = devices
            except ValueError, e:
                # Get device from user input
                devices = dict(enumerate(devices))
                sep = self.colorText("|", "separators")
                item = "{num} {sep} {dName} {sep} {currency} {sep} {id}"
                header = item.format(
                    num      = "#".rjust(4),
                    dName    = "Device".ljust(25),
                    currency = "CRY",
                    id       = "ID",
                    sep      = sep
                    )
                print self.colorText(header, "shell_self")
                print self.colorText(" " + "-"*78, "separators")
                for num,dev in devices.iteritems():
                    dItem = item.format(
                        num      = str(num).rjust(4),
                        dName    = dev.name.ljust(25),
                        currency = dev.standard,
                        id       = dev.id,
                        sep      = sep
                        )
                    print self.colorText(dItem,"shell_self")
                num = u""
                print ""
                while not num.isdigit() or not devices.has_key( int(num) ):
                    num = raw_input(self.colorText("Device: ","shell_self"))
                device = devices[int( num )]
        else:
            raise InputError("Invalid XML: No device found",
                             kind = "XML", arg = "No device found" )
        return device
    
    def _interactive_pw(self):
        u"Get password from user, nicely colored."
        pw = u""
        while not pw:
            # Prompt user to provide password to decrypt secret
            pw = getpass.getpass(self.colorText("Password: ","shell_self"))
        return pw

    def _shell_buy(self, opts, args):
        u"Post bid-order at Mt.Gox, buying bitcoins."
        if len(args):
            asbtc, val = self._match_sign(opts.currency, args[0])
            opts.asbtc = asbtc
            args[0]    = val
        json   = self.request("buy", self._action_buy(opts, args))
        parsed = JsonParser.parse(json)
        text   = self.colorText("Added bid: ", "shell_self")
        oid    = self.colorText(parsed["return"], "order_bid")
        print u"{0}{1}".format(text, oid)

    def _shell_clear(self, opts, args):
        u"Clear all orders in orderlist.\n"\
        u"clear [type]\n" \
        u"[type] Order type, could be either ask or bid (Leave it unset to remove all orders).\n"
        if len(args) > 1:
            raise InputError("Expected 0 or 1 arguments, got %s" % len(args))
        elif not len(args):
            sides = ("bid","ask")
        elif args[0] in ("bid","ask"):
            sides = (args[0],)
        else:
            raise InputError("Invalid argument: %s" % args[0], arg=args[0])
        orders = self.request("orders")
        orders = JsonParser.parse(orders)["return"]
        sep    = self.colorText( "|", "separators" )
        print u"      {sep}    {amount}   {sep} {id}".format(
            kind   = self.colorText("Kind", "shell_self"),
            amount = self.colorText("Size (BTC)", "order_amount"),
            id     = self.colorText("ID of the cancelled order",  "shell_self"),
            sep    = sep
            )
        print self.colorText( (u"="*78).center(80), "separators" )
        for order in orders:
            kind   = order["type"]
            amount = Decimal(order["amount"]["value"])
            oid    = order["oid"]
            if kind in sides:
                self.request("cancel", { "kind": kind, "oid": oid })
                amount = format( amount, ".8f" ).rjust(15)[:15]
                kind   = self.colorText(kind,         "order_%s" % kind)
                amount = self.colorText(amount,       "order_amount")
                oid    = self.colorText(order[u"oid"],"order_oid")
                print "  {kind} {sep} {amount} {sep} {oid}".format(
                    kind   = kind,
                    amount = amount,
                    oid    = oid,
                    sep    = sep
                    )

    def _shell_daemon(self, opts, args):
        u"Start or kill Daemon, background-service providing credentials" \
        u" for other applications through IPC as well as if you want to" \
        u" run this client with actions that requires authentication" \
        u" directly from command-line.\n" \
        u"daemon <start/kill>\n" \
        u"<start/kill> Switch, will kill or start the daemon respectively"
        if not args:
            switch = None
        else:
            try:
                switch, = args
            except ValueError:
                raise InputError("Expected 1 argument, got %s" % len(args))
            else:
                try:
                    switch = {"start":True,"kill":False}[switch.lower()]
                except KeyError:
                    raise InputError("Invalid argument: " + switch, arg=switch)
        try:
            json = DaemonIPC.send(r'{"action": "Terminate"}')
        except DaemonError:
            if switch == None:
                switch = True
        if switch:
            json   = Daemon(self.xml).run()
            parsed = JsonParser.parse(json)
            if parsed["return"] == "1":
                text = "Daemon now listening on IPC"
            else:
                text = u"Daemon now listening on TCP, accepting  incoming" + \
                        " local connections on port %s" % listening
        else:
            # Kill main daemon
            parsed = JsonParser.parse(json)
            text   = "Daemon says: %s" % parsed["return"]
        print self.colorText(text, "shell_self")

    def _shell_delete(self, opts, args):
        u"Delete device containing credentials.\n" \
        u"delete [id] [id] [...]\n" \
        u"[id] Specify for which device you no longer want to provide" \
        u" credentials."
        if args:
            if hasattr(args, "__iter__"):
                for id in args:
                    # Get device for every ID to check if it exist
                    device = self.xml.getDevice(id)
                    if not device:
                        self._error(
                            InputError(
                                "Invalid id: %s" % id,
                                 kind = "id", arg = id
                                 )
                            )
                        return
                    # Call this function again with every id retrieved
                    self._shell_delete(opts, id)
                return
            else:
                id = args
        elif len(self.xml.devices) == 1:
            id = self.xml.devices[0]
        else:
            id = self._interactive_device(self.xml.devices).id
        try:
            json   = self._action_delete(opts, [id])
        except DaemonError, e:
            self._error(e)
        else:
            text   = "Deleted device: %s" % id
            print self.colorText(text, "shell_self")

    def _shell_read_delete(self, json):
        u"Print successfully deleted devices."
        json = JsonParser.parse(json)
        if not json["return"]:
            print self.colorText("Found no device(s) to delete","error_message")
        else:
            print self.colorText(" Deleted ID(s): ", "shell_self")
            for id in json["return"]: print self.colorText("  " + id, "shell_self")

    def _shell_read_devices(self, json):
        u"Print devices in config."
        sep   = self.colorText("|", "separators")
        line  = self.colorText(("-"*78).center(60), "separators")
        dLine = self.colorText(("="*78).center(60), "separators")
        item  = u" {name} {cry} {sep} {id} {sep} {enc} {sep} {listen}\n{line}"
        print self.colorText(
            item.format(
                name   = "Name".ljust(20),
                cry    = "".ljust(3),
                id     = "ID".ljust(33),
                listen = "Daemon",
                enc    = "Encr",
                sep    = sep,
                line   = dLine
                ),
                "shell_self"
            )
        for device in JsonParser.parse(json)["return"]:
            listening  = "True" if device["listening"] == "True" else ""
            encrypted  = "True" if device["encrypted"] == "True" else ""
            print self.colorText(
                item.format(
                    standard  = device["standard"],
                    name      = device["name"].ljust(20)[:20],
                    id        = device["id"],
                    listening = listening.ljust(4),
                    encrypted = encrypted.ljust(4),
                    sep       = sep,
                    line      = line
                    ),
                "shell_self"
                )
    
    def _shell_read_activate(self, json):
        u"Confirm activation."
        #self.xml.read()
        json       = JsonParser.parse(json)
        device     = json["return"]["id"]
        name       = json["return"]["name"]
        print self.colorText("Successfully activated device.", "shell_self")
        print self.colorText("Name: %s" % name, "shell_self")
        print self.colorText("ID  : %s" % device, "shell_self")

    def _shell_sell(self, opts, args):
        u"Post ask-order at Mt.Gox, buying bitcoins."
        if len(args):
            opts.asbtc = self._match_sign(opts.currency, args[0])
        json   = self.request("sell", self._action_sell(opts, args))
        parsed = JsonParser.parse(json)
        text   = self.colorText("Added ask: ", "shell_self")
        oid    = self.colorText(parsed["return"], "order_ask")
        print u"{0}{1}".format(text, oid)

    def _match_sign(self, currency, value):
        match = self.re_sign[currency].match(value.decode("utf-8"))
        if match:
            value = match.group(2) if match.group(2) else match.group(1)
            return False,value
        else:
            return True,value

    def _shell_read_cancel(self, json):
        u"Cancel trade from type and oid."
        self._shell_read_orders(json, old = True)

    def _shell_currency(self, opts, args):
        u"Change active currency.\n"\
        u"currency <CRY>\n"\
        u"<CRY> Currency as a three letter code (e.g. USD/EUR/SEK)."
        if len(args) == 1:
            cry = args[0].upper()
            if cry != "BTC":
                self.opts.currency = cry
                prefix, symbol     = self.xml.currency(cry)
                cryStr = u"Active currency changed to: {0}".format(cry)
                symStr = u"Currency-symbol (Prefix/suffix): {0}".format(symbol)
                print self.colorText(cryStr, "shell_self")
                print self.colorText(symStr, "shell_self")
        else:
            raise InputError("Expected 1 argument, got %s" % len(args))

    def _shell_read_deposit(self, json):
        u"Requests address for depositing BTC to your wallet at Mt.Gox."
        json = JsonParser.parse(json)
        addr = u"Address: {0}".format(json["return"]["addr"])
        print self.colorText(addr,"shell_self")

    def _shell_read_depth(self, json):
        u"Parse, read and print json from depth-action."
        json  = JsonParser.parse(json)
        pForm = ".%sf" % self.xml.currencies[self.opts.currency]["decimals"]
        sep   = self.colorText("|", "separators")
        line  = self.colorText(("-"*78).center(80), "separators")
        dLine = self.colorText(("="*78).center(80), "separators")
        if json["return"]["bids"]:
            ex = json["return"]["bids"][0]
        elif json["return"]["asks"]:
            ex = json["return"]["asks"][0]
        else:
            print self.colorText(u"Table is empty.","shell_self")
            return
        if ex.has_key("value"):
            value = True
            header = sep.join((
                u"  Type  ","    Price    ","      Amount       ","       Value"
                ))
        else:
            value = False
            header = sep.join((
                u"   Type ","    Price    ","      Amount"
                ))
        print self.colorText(header,"shell_self")
        print dLine
        for side in ("asks","gap","bids"):
            color = "depth_{0}".format(side)
            type  = side.capitalize()[:3]
            type  = self.colorText(type, "shell_self")
            if side == "gap":
                if all((json["return"]["bids"],json["return"]["asks"])):
                    # Printing info about gap (if included)
                    try:
                        upper = format(json["return"]["gap"]["upper"], pForm)
                        lower = format(json["return"]["gap"]["lower"], pForm)
                        price = str(Decimal(upper) - Decimal(lower))
                    except KeyError:
                        print self.colorText(line, "separators")
                    else:
                        vals = []
                        vals.append(
                            self.colorText(
                                upper.rjust(11)[:11],
                                "shell_self"
                                )
                            )
                        vals.append(
                           self.colorText(
                                price.rjust(11)[:11],
                                color
                                )
                           )
                        vals.append(
                            self.colorText(
                                lower.rjust(11)[:11],
                                "shell_self"
                                )
                            )
                        print self.colorText(line, "separators")
                        for val in vals:
                            print u"   {type}  {sep} {val}".format(
                                type = type,
                                sep  = sep,
                                val  = val
                                )
                        print self.colorText(line, "separators")
            else:
                orders = reversed(json["return"][side])
                for o in orders:
                    price  = format(o["price"],    pForm)
                    price  = price.rjust(11)[:11]
                    price  = self.colorText(price, color)
                    amount = format(o["amount"],   '.8f')
                    amount = amount.rjust(16)[:16]
                    amount = self.colorText(amount, "shell_self")
                    if value:
                        value = format(o["value"], pForm)
                        value = value.rjust(17)
                        value = "  ".join((sep,value))
                        value = self.colorText(value, "shell_self")
                    else:
                       value = str()
                    order = u"   {0}  {sep} {1} {sep} {2}  {3}"
                    print order.format(type, price, amount, value, sep = sep)
        if not json["return"]["bids"]:
            lower = Decimal(json["return"]["gap"]["lower"])
            lower = format(lower, pForm)
            lower = lower.rjust(11)[:11]
            lower = self.colorText(lower, "shell_self")
            print self.colorText(
                u"   {type}  {sep} {lower}".format(
                    type  = "Low",
                    sep   = sep,
                    lower = lower
                    ),
                "shell_self"
                )

    def _shell_exit(self,opts=None,args=None):
        u"Exit GoxCLI.\n" \
        u"exit"
        raise EOFError()

    def _shell_help(self, opts, args):
        u"Show this help.\n" \
        u"help [command]\n" \
        u"[command] Only show help for a specific command."
        if not args:
            print "\n".join((
                "<Arguments> is required while [arguments] is optional\n",
                "Also, keyword arguments accept different kinds of values.",
                "int  = Integer, whole numbers only.",
                "str  = String, can contain alphabet," + \
                " numbers and sometimes currency-symbols.",
                "dec  = Decimal, decimal or whole numbers.",
                "bool = Boolean, accepts True or False. (Option is not case" + \
                " sensitive)\n"))
            # Matches attributes in self against _shell_* OR _shell_read_*
            exp  = re.compile(r"^_shell_(?:read_)?(.+)$")
            cmds = self._get_cmds(exp)
        else:
            cmds = args
        for cmd in cmds:
            self.__print_cmd_info(cmd)
    
    def __print_cmd_info(self, cmd):
        u"Collect docstrings and print them."
        try:
            # ShellHandler overrides function, local docstring contains
            #   descriptions of command and arguments as well as an example.
            proc = getattr(self, "_shell_{0}".format(cmd))
        except AttributeError, e:
            # ShellHandler does not override this action.
            try:
                # Look for description in MtGoxAPI.
                proc  = getattr(self.api, cmd)
            except AttributeError:
                # Action not found in MtGoxAPI, must be a custom function with
                #   all info described in ClientHandler.
                proc  = getattr(self, "_action_{0}".format(cmd))
                doc   = proc.__doc__.splitlines()
                descr = doc.pop(0)
            else:
                # Description of action found in MtGoxAPI.
                descr = proc.__doc__.splitlines().pop(0)
                # Change docstring to one from ClientHandler which contains
                #   command-line example and argument specifications.
                proc = getattr(self, "_action_{0}".format(cmd))
                doc  = proc.__doc__.splitlines()
        else:
            doc   = proc.__doc__.splitlines()
            descr = doc.pop(0)
            if not len(doc):
                # Only description found in local function, reading example and
                #   argument specifications from ClientHandler.
                proc = getattr(self, "_action_{0}".format(cmd))
                doc  = proc.__doc__.splitlines()
                del doc[0]
        # Reading next line (should contain example cmd-line)
        ce = doc.pop(0)
        print "\n"
        for space, line in self.__help_format_line(ce, 79, len(cmd)+1):
            print u" {0}{1}".format(space, self.colorText( line, "shell_help_cmd" ) )
        for space, line in self.__help_format_line(descr, 78, 2):
            print u"  {0}{1}".format(space, self.colorText( line, "shell_help_descr" ) )
        while doc:
            print ""
            line = doc.pop(0)
            for s,l in self.__help_format_line(line, 77, 2, rJust = 15):
                print u"{0} {1}".format(
                    self.colorText(s, "shell_help_arg"),
                    self.colorText(l, "shell_self")
                    )

    def _shell_history(self, opts, args):
        u"Request history of your wallet in current currency.\n"\
        u"history [BTC] [all=bool]\n"\
        u"[BTC] Apply BTC as a single argument to request the history of your" \
        u" BTC-wallet."
        u"[all=bool] Show all pages provided by API, not just the latest one."
        fh  = False
        currency = opts.currency
        if args:
            if len(args) > 2:
                m = u"History takes 0, 1 or 2 arguments, recieved %s" % len(args)
                raise InputError(m)
            for arg in args:
                # Split key-word arguments
                try:
                    key,value = arg.split("=")
                except ValueError:
                    if arg.upper() == u"BTC":
                        currency = arg.upper()
                    else:
                        raise InputError(u"Invalid argument: %s" % arg, arg=arg)
                else:
                    if key.lower() == "all":
                        if value.lower() == "true":
                            fh = True
        trades = list()
        page   = 1
        while page:
            args = {
                "currency": currency,
                "page": page
                }
            json = self.request( "history", args )
            json = JsonParser.parse( json )
            trades.extend( json["return"]["result"] )
            if page < int( json["return"]["max_page"] ) and fh:
                page += 1
            else:
                page = False
        pForm  = ".%sf" % self.xml.currencies[self.opts.currency]["decimals"]
        sep    = self.colorText( "|", "separators" )
        dLine  = self.colorText( "="*80, "separators" )
        line   = self.colorText( "-"*80, "separators" )
        id     = trades[0]["Link"][2]
        head   = ()
        header = "  Type  {0}     Value     {0}    Balance    {0}  Fee / Price"
        print header.format(sep)
        dLine
        for i in reversed(trades):
            kind  = i["Type"]
            value = Decimal(i["Value"]["value"])
            if kind == "fee":
                info   = i["Info"].split()[-2] + ")"
                value *= -1
                color  = "history_fee"
            elif kind in ("spent", "earned","in","out"):
                info = " ".join(i["Info"].split()[-4:])
                if kind in ("spent","out"):
                    value *= -1
                    color  = "history_spend"
                else:
                    color  = "history_earn"
            else:
                info = ""
            kind  = kind.capitalize().ljust(8)
            value = format(value, pForm)
            value = str(value).rjust(13)[:13]
            value = self.colorText(value, color)
            balance = Decimal(i["Balance"]["value"])
            balance = format(balance, pForm)
            balance = str(balance).rjust(13)[:13]
            balance = self.colorText(balance, "history_balance")
            print "{0}{sep} {1} {sep} {2} {sep} {3}".format(
                kind,
                value,
                balance,
                info,
                sep = sep
                )
            if id != i["Link"][2]:
                print line
                id = i["Link"][2]

    def _shell_read_info(self, json):
        u"Read and print parsed json from info-action conatining info about" \
        u" your account at Mt.Gox."
        json  = JsonParser.parse(json)
        user  = json["return"]["Login"]
        sep   = self.colorText("|", "separators")
        line  = self.colorText(("-"*78).center(80), "separators")
        dLine = self.colorText(("="*78).center(80), "separators")
        if "get_info" in json["return"]["Rights"]:
            vol = json["return"]["Monthly_Volume"]["value"]
            vol = u"30d Volume : {0}".format(vol)
            fee = u"Fee : {0}%".format(json["return"]["Trade_Fee"])
            s = u"    User : {user} {sep} {vol} {sep} {fee}"
            print self.colorText(
                    s.format(
                        user = user.ljust(15)[:15], 
                        vol  = vol.center(27)[:27],
                        fee  = fee.center(19)[:19],
                        sep  = sep
                        ), "shell_self"
                    )
            print dLine
            s = "{wallet} {sep} {balance} {sep} {ops} {sep} {day} {sep} {month}"
            print self.colorText(
                s.format(
                    wallet  = "  Wallet",
                    balance = "    Balance    ",
                    ops     = "  Ops  ",
                    day     = "Daily Withdrawals",
                    month   = "Monthly Withdrawals",
                    sep     = sep
                    ), "shell_self"
                )
            print line
            wallets = json[u"return"][u"Wallets"]
            for currency,data in wallets.iteritems():
                ops     = str(data[u"Operations"])
                balance = data[u"Balance"][u"value"]
                day     = data["Daily_Withdraw_Limit"][u"value"]
                month   = data[u"Monthly_Withdraw_Limit"]
                month   = month[u"value"] if month else u"None"
                s = u" {cur} {sep} {bal} {sep} {ops} {sep} {day} {sep} {month}"
                print self.colorText(
                        s.format(
                            cur   = currency.rjust(7),
                            bal   = balance.rjust(15)[:15],
                            ops   = ops.rjust(7)[-7:],
                            day   = day.rjust(17)[:17],
                            month = month.rjust(19)[:19],
                            sep   = sep
                        ), "shell_self"
                    )
        else:
            print u"    User : {0}".format(user)
        print dLine
        rs = u"  Rights : "
        for s,r in ((u"Info",    u"get_info"),
                    (u"Trading", u"trade"   ),
                    (u"Deposit", u"deposit" ),
                    (u"Withdraw",u"withdraw"),
                    (u"Merchant",u"merchant")):
            if r in json[u"return"][u"Rights"]:
                rs += "".join(("  ", s," [X]"))
            else:
                rs += "".join(("  ", s," [ ]"))
        print self.colorText(rs,"shell_self")

    def _shell_kill(self, opts, args):
        u"Kill Daemon, background-service providing credentials to other" \
        u"instances (most likely command-line executed)\n" \
        u"kill"
        try:
            json = self.killService(device)
        except DaemonError, e:
            self._error(e.message)
        else:
            text = "Stopped service: %s (%s)" % (device.id, device.name)
            print self.colorText(text, "shell_self")

    def _shell_login(self, opts, args):
        u"Load and decrypt/decode secret from config.\n"\
        u"login [daemon=bool]\n"\
        u"[daemon=bool] Provide credentials to other instances, daemon must" \
        u" be running in order to use this option. (See action daemon)"
        daemon, handshake = False, False
        if args:
            if len(args) > 2:
                raise InputError("Expected 0, 1 or 2 arguments, got %s" % len(args))
            for arg in args:
                try:
                    k,v = args[0].lower().split("=")
                    if k == "daemon":
                        daemon = {"true":True, "false":False}[v]
                    else:
                        raise InputError("Invalid argument: %s" % k, arg = k)
                except KeyError:
                    raise InputError("Invalid value: %s" % value,
                                     kind = "value", arg = value)
        device = self._interactive_device()
        if device.length:
            pw = self._interactive_pw()
        if daemon:
            json = JsonParser.build({
                "action" : "login",
                "id"     : device.id,
                "pw"     : pw
                })
            json   = DaemonIPC.send( json )
            parsed = JsonParser.parse(json)
            if self.xml.handshakes:
                handshake = parsed["return"]
                self._handshakes[device.id] = handshake
            text = "Daemon is now providing services for: "
            print "\n{0}{1}".format(
                self.colorText(text, "shell_self"),
                self.colorText(device.name,       "shell_device"))
            print "{0}{1}".format(
                self.colorText("Handshake: ",   "shell_self"),
                self.colorText(handshake,        "shell_user") )
            try:
                info = self.request("info")                
            except:
                m = "\nCould not verify log in, please check password and connection"
                self._error(m)
            else:
                info = JsonParser.parse(info)
                self.user = info["return"]["Login"]
        else:
            if device.length:
                secret = Crypter.decrypt(device.secret, pw, device.length)
            self.credentials = (device, secret)
            if self.user:
                print "\n{0}{1}".format(
                    self.colorText("Using device: ", "shell_self"),
                    self.colorText(self.dName,       "shell_device"))
                print "{0}{1}".format(
                    self.colorText("Belongs to: ",   "shell_self"),
                    self.colorText(self.user,        "shell_user") )
            else:
                m = "Could not log in, please check password and connection"
                self._error(m)

    def _shell_logout(self, opts, args, verbose=True):
        u"Unload secret and device-information.\n" \
        u"logout"
        if self._secret:
            self.user      = None
            self.device    = None
            self._standard = None
            self._key      = None
            self._secret   = None
            self._counter  = 0
        else:
            if self.device:
                json = JsonParser.build({
                    "action" : "logout",
                    "handshake" : self.handshake,
                    })
                json = DaemonIPC.send( json )
                if json == r'{"result": "success"}':
                    self.user      = None
                    self.device    = None
                    self._standard = None
                    if verbose:
                        print self.colorText("Logged out", "shell_self")
                else:
                    self._error("Could not log out")
            else:
                raise CredentialError("No credentials saved in client.")

    def _shell_read_orders(self, json, old = False, all = False):
        u"Read and print parsed json from order-action, containing your open," \
        u" invalid or pending orders."
        json     = JsonParser.parse(json)
        currency = self.opts.currency
        pForm    = ".%sf" % self.xml.currencies[currency]["decimals"]
        dLine    = self.colorText( (u"="*78).center(80), "separators" )
        line     = self.colorText( (u"-"*78).center(80), "separators" )
        sep      = self.colorText( "|", "separators" )
        print u"  {kind} {sep}       {amount}       {sep} {id}".format(
            kind   = self.colorText("Ask", "order_ask"),
            amount = self.colorText("BTC", "order_amount"),
            id     = self.colorText("ID",  "shell_self"),
            sep    = sep
            )
        print u"  {kind} {sep}      {price}      {sep} {date}".format(
            kind  = self.colorText("Bid",           "order_bid"),
            price = self.colorText("Price",         "order_price"),
            date  = self.colorText("Date (status)", "shell_self"),
            sep   = sep
            )
        print dLine
        if old:
            orders = json[u"orders"]
        else:
            orders = json[u"return"]
        for order in orders:
            if all or order[u"currency"] == currency:
                if old:
                    old = self.__read_old_order(order)
                    cry,kind,amount,price,date,status = old
                else:
                    cry      = "   "
                    amount   = Decimal( order[u"amount"]["value"] )
                    price    = Decimal( order[u"price"]["value"]  )
                    kind     = order[u"type"]
                    kColor   = "order_%s" % kind.lower() 
                    status   = order[u"status"]
                    date     = datetime.fromtimestamp( int(order[u"date"]) )
                    date     = date.strftime("%Y-%m-%d %H:%M:%S")
                amount = format( amount, ".8f" ).rjust(15)[:15]
                price  = format( price , pForm ).rjust(15)[:15]
                kind   = self.colorText(kind,         "order_%s" % kind)
                amount = self.colorText(amount,       "order_amount")
                oid    = self.colorText(order[u"oid"],"order_oid")
                price  = self.colorText(price,        "order_price")
                date   = self.colorText(date,         "order_time")
                status = self.colorText(" (" + status + ")",    "shell_self")
                print "  {kind} {sep} {amount} {sep} {oid}".format(
                    kind   = kind,
                    amount = amount,
                    oid    = oid,
                    sep    = sep
                    )
                print "  {currency} {sep} {price} {sep} {date}{status}".format(
                    currency = cry,
                    price    = price,
                    date     = date,
                    status   = status,
                    sep      = sep
                    )
                print self.colorText(line, "shell_self")
            else:
                print currency

    def __read_old_order(self,order):
        u"Reads order-type for the API v0, API v1 still returns that kind of" \
        u" list when cancelling orders."
        currency = order[u"currency"]
        pForm    = ".%sf" % self.xml.currencies[currency]["decimals"]
        kind     = {1: u"ask", 2: u"bid"}[order[u"type"]]
        amount   = Decimal( order[u"amount"] )
        price    = Decimal( order[u"price"]  )
        date     = int(order[u"date"])
        date     = datetime.fromtimestamp(date).strftime( "%Y-%m-%d %H:%M:%S" )
        status   = order[u"real_status"]
        return currency, kind, amount, price, date, status

    def _shell_profit(self, opts, args):
        u"Calculate profitable short/long prices for a given initial price," \
        u" taking into account Mt. Gox's commission fee.\n" \
        u"profit <price>\n" \
        u"<price> Price as decimal."
        if len(args) != 1:
            raise InputError("Expected 1 argument, got %s" % len(args))
        json  = self.request("info")
        json  = JsonParser.parse(json)
        fee   = Decimal(json["return"][u"Trade_Fee"])/100
        cPrec = (Decimal(1) / 10) ** self.xml.currencies[opts.currency]["decimals"]
        price = Decimal(args[0])
        if price < 0:
            raise InputError( u"Invalid price: %s" % price,
                              kind = "price" , arg = price )
        ratio = (1 - fee)**(-2)
        short = (price / ratio).quantize(cPrec)
        long  = (price * ratio).quantize(cPrec)
        print "{0} <> {1}".format(
            self.colorText(short, "trades_down"),
            self.colorText(long,  "trades_up"),)

    def _shell_read_status(self, json):
        u"Reads parsed json returned from status-action."
        json   = JsonParser.parse(json)
        trades = json["return"]["trades"]
        if trades:
            sep   = self.colorText("|", "separators")
            line  = self.colorText(("-"*61).center(63),"separators")
            dLine = self.colorText(("="*61).center(63),"separators")
            oid   = json["return"]["order_id"]
            total = json["return"]["total_amount"]["display_short"]
            total = u" Total amount: {0} ({1})".format(total, oid)
            print self.colorText(total,"shell_self")
            print dLine
            amount = u"Amount".center(16)[:16]
            price  = u"Price".center(11)[:11]
            date   = u"Date".center(19)[:19]
            header = " {amount} {sep} {price} {sep} {date}".format(
                amount = amount,
                price  = price,
                date   = date,
                sep    = sep
                )
            print self.colorText(header, "shell_self")
            print line
            for t in trades:
                amount = t[u"amount"]["value"].rjust(16)[:16]
                price  = t[u"price"]["value"].rjust(11)[:11]
                date   = t[u"date"]
                trade  = " {amount} {sep} {price} {sep} {date}".format(
                    amount = amount,
                    price  = price,
                    date   = date,
                    sep    = sep
                )
                print self.colorText(trade,"shell_self")
        else:
            print self.colorText(u" Order is still intact.","shell_self")

    def _shell_read_ticker(self, json):
        u"Reads and display ticker."
        json   = JsonParser.parse(json)
        ticker = json["return"]
        pForm  = ".%sf" % self.xml.currencies[self.opts.currency]["decimals"]
        for i in ("high","buy","last","sell","low","avg","vol"):
            value = Decimal( ticker[i]["value"] )
            if i != "vol":
                value = format(value, pForm).rjust(10)
            else:
                value = format(value, '.5f').rjust(10)[:10]
            text = i.capitalize().rjust(4) + ": "
            text = self.colorText(text, "shell_self")
            value = self.colorText(value, "ticker_" + i)
            print u"{0}{1}".format(text, value)

    def _shell_read_trades(self, json):
        u"Reads and display parsed json containing trades returned by Mt.Gox."
        json    = JsonParser.parse(json)
        pForm   = ".%sf" % self.xml.currencies[self.opts.currency]["decimals"]
        sep     = self.colorText("|", "separators")
        line    = self.colorText(("-"*61).center(63), "separators")
        amount  = u"Amount".center(18)[:18]
        price   = u"Price".center(11)[:11]
        date    = u"Date".center(19)[:19]
        header  = " Type {sep} {amount} {sep} {price} {sep} {date} ".format(
            amount = amount,
            price  = price,
            date   = date,
            sep    = sep
            )
        print self.colorText(header, "shell_self")
        print line
        trades = json["return"]
        try:
            pPrice = Decimal(trades[0][u"price"])
        except IndexError:
            empty = "Mt.Gox returned empty table".center(63)
            print self.colorText(empty, "shell_self")
        for trade in trades:
            price = Decimal(trade[u"price"])
            if price < pPrice:   color = "trades_down"
            elif price > pPrice: color = "trades_up"
            else: color = "trades_con"
            pPrice = price
            kind   = trade[u"trade_type"].decode("string_escape")
            kind   = self.colorText(kind, "shell_self")
            price  = format(price, pForm).rjust(11)[:11]
            price  = self.colorText(price,color)
            amount = Decimal(trade[u"amount"])
            amount = format(amount, '.8f').rjust(18)[:18]
            amount = self.colorText(amount, "shell_self")
            date   = int(trade[u"date"])
            date   = datetime.fromtimestamp(date).strftime("%Y-%m-%d %H:%M:%S")
            date   = date.center(19)[:19]
            date   = self.colorText(date,"shell_self")
            item   = "  {kind} {sep} {price} {sep} {amount} {sep} {date}"
            print item.format(
                kind   = kind,
                price  = price,
                amount = amount,
                date   = date,
                sep    = sep
                )

    def _shell_read_withdraw(self, json):
        json = JsonParser.parse(json)
        print self.colorText(json[u"status"], "shell_self")

    def _startLogin(self):
        if self.opts.id:
            device = self.xml.getDevice(self.opts.id)
        else:
            devices = self.xml.devices
            try:
                device, = devices
            except ValueError, e:
                device = None
        if not device or device.length:
            standard = device.standard if device else "USD"
            self.api.standard  = standard
            self.opts.currency = standard
        else:
            json = self.request("info")
            try:
                json = JsonParser.parse( json )
            except (CredentialError, DaemonError):
                pass
            except ParseError, e:
                print self._error(e.message, "shell_self")
            except (urllib2.URLError, urllib2.HTTPError), e:
                print self.colorText("Could not login: \"%s\"" % e,"shell_self")
            else:
                self.user   = json["return"]["Login"]
                self.device = device
                print "\n{0}{1}".format(
                    self.colorText("Using device: ", "shell_self"),
                    self.colorText(self.dName, "shell_device")
                    )
                print "{0}{1}".format(
                    self.colorText("Belongs to: ", "shell_self"),
                    self.colorText(self.user, "shell_user")
                    )

    def _xmlSetup(self):
        # Read and parse full xml.document
        self.xml.read(self.opts.xml, colors = True, currencies = True)
        # Get reset-color (ansi)
        self.creset = self.xml.colors.get("reset", "\033[0;0m")
        self.creset = self.creset.decode("string_escape")
        # Setup a dictionary with compiled regexps matching all currency-symbols
        # TODO: Write better re...
        regexp = ur"^\{0}(\d*\.?\d+)$|^(\d*\.?\d+)\{0}$"
        self._re_compile = lambda c: \
            re.compile(
                regexp.format(
                    self.xml.currencies[c]["prefix"]
                )
            )
        gen = ((c,self._re_compile(c)) for c in self.xml.currencies.iterkeys())
        self.re_sign = dict( gen )
        # Set tokens, TODO: strip
        collapse_escapes   = partial(re.compile(r"\\(.)",re.UNICODE).sub,"\\g<1>")
        self.__token_types = (
            ( # naked (unquoted)
                re.compile(r"(?:\\[\s\\\"';#]|[^\s\\\"';#])+", re.UNICODE),
                collapse_escapes
            ),
            ( # double-quoted
                re.compile(r"\"(?:\\[\\\"]|[^\\])*?\"", re.UNICODE),
                lambda matched: collapse_escapes(matched[1:-1])
            ),
            ( # single-quoted
                re.compile(r"'(?:\\[\\']|[^\\])*?'", re.UNICODE),
                lambda matched: collapse_escapes(matched[1:-1])
            ),
            ( # whitespace and comments
                re.compile(r"(?:\s|#.*)+", re.UNICODE),
                lambda matched: None
            ),
            ( # semicolon
                re.compile(r";", re.UNICODE),
                lambda matched: matched
            )
        )

    def colorText(self, text, colorName, reset = True):
        u"Returns a string containing colored text."
        color = self.xml.colors.get(colorName, "\033[0;0m").decode("string_escape")
        color = color.decode("string_escape")
        reset = self.creset if reset else ""
        return u"{color}{text}{reset}".format(
            color = color,
            text  = text,
            reset = reset
            )

    def perform(self, cmd, args):
        u"Passes commands on to appropriate functions."
        try:
            # Look for private function in self (ShellHandler)
            proc = getattr(self, "_shell_{0}".format(cmd), None)
            if proc:
                proc(self.opts,args)
            else:
                # Arguments need no special parsing.
                args.insert(0, cmd)
                json = self.action(self.opts, args)
                # Reading json with shell-specific function.
                proc = getattr(self, "_shell_read_{0}".format(cmd), None)
                if proc:
                    proc(json)
                else:
                    # Function cannot be printed
                    pass
        except InvalidOperation, e:
            # Error when trying to convert string to Decimal
            v = e.message.rpartition(" ")[2].lstrip("u\'").rstrip("'")
            self._error("Invalid value: %s " % v, v)
        except (EOFError, TokenizationError, KeyboardInterrupt), e:
            # Exit loop
            raise e
        except (InputError, RightError, CredentialError, DaemonError), e:
            # Input or credential-related errors
            message = e.msg if hasattr(e, "msg") else e.message
            arg     = e.arg if hasattr(e, "arg") and e.arg else ""
            self._error(message, arg)
        except ParseError, e:
            self._error(u"Error:",e.message)
        #except urllib2.HTTPError,e:
        #    # Error occurred while trying to reach Mt.Gox.
        #    self._error("HTTP Error:"," ".join((str(e.code),e.msg)))

    def prompt(self):
        u"Takes user input, parse commands and then passes them on to perform."
        procs = []
        args = []
        try:
            raw_line = None
            try:
                out = "\n{dName}@{user}:{currency}$ "
                out = out.format(
                    dName = self.dName,
                    user  = self.user,
                    currency = self.opts.currency
                    )
                line = raw_input(out)
                print ""
            except EOFError, e:
                print self.colorText(u"exit","shell_self")
                self._shell_exit()
            commands = self.__parse_tokens(self.__tokenize_command(line))
            for ca in commands:
                self.perform(*ca)
        except EOFError, e:
            raise e
        except Exception, e:
            traceback.print_exc()

    def run(self, encoding):
        u"Run shell-variant of GoxCLI."
        # Setup tabcompletion
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.__complete)
        self.__encoding    = encoding
        # Load XML-file and set up regexps
        self._xmlSetup()
        # Load device if specified or if only one device is found in config.
        self._startLogin()
        print self.colorText(u"\nWelcome to GoxCLI!","shell_self")
        print self.colorText(u"Type 'help' to get started.","shell_self")
        try:
            while True:
                self.prompt()
        except EOFError:
            pass