#!/usr/bin/env python
import os,sys

from datetime import datetime
from functools import partial
from decimal import Decimal,InvalidOperation
from optparse import OptionParser,OptionGroup

# Regular expression-support
import re

# HTTP, SSL and Pipes
from ssl import SSLError
from contextlib import closing
import socket
import urllib
import urllib2

# Encoding, and encrypting
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import binascii
import base64
import hmac
import hashlib

# Json-Support
# Slow json only needed for prettyprint, should add regexps instead.
import json, cjson

import xml.dom.minidom
import readline
import random
import uuid
import getpass
import string
import traceback
import locale
import time


class CredentialError(Exception): pass

class RightError(Exception):
    def __init__(self, message, right=None, kind=None, arg=None):
        self.msg = "Need %s rights to use %s %s" % (right, kind, arg)

class InputError(Exception):
    def __init__(self, message, arg=None, kind=None):
        if arg:
            self.arg = arg
            self.msg = "Invalid %s:" % (kind if kind else "argument")
        else:
            self.msg = message
            self.arg = u""
        Exception.__init__(self, message)

class MtGoxError(Exception):
    pass

class DaemonError(Exception):
    pass

class TokenizationError(Exception):
    pass


class JsonParser:
    @staticmethod
    def parse(obj, force = False):
        u"Parse json-strings."
        # cjson is fast and good enough for our purposes
        json = cjson.decode(obj)
        if u"error" in json and not force:
            raise MtGoxError(json[u"error"])
        else:
            return json

    @staticmethod
    def build(obj):
        u"Build json-strings from object(s)."
        return cjson.encode(obj)


class XmlParse(object):
    def __init__(self, path):
        u"Parse config-file in XML-format."
        self.path       = path
        self.doc        = None
        self.cfg        = None
        self.colors     = None
        self.currencies = None

    def _deviceNode(self, id, name, standard, credentials):
        u"Construct deviceNodes from values."
        # Create top node of device
        dNode = self.doc.createElement(id)
        dNode.setAttribute("name", name)
        dNode.setAttribute("standard", standard)
        # Unpack credentials and create credential-node
        port, key, length, secret = credentials
        # Key-node
        kNode = self.doc.createElement("key")
        kNode.setAttribute("value", str(key))
        # Port-node
        pNode = self.doc.createElement("port")
        pNode.setAttribute("value", str(port))
        # Secret-Node
        sNode = self.doc.createElement("secret")
        sNode.setAttribute("length", str(length))
        sNode.appendChild(self.doc.createTextNode(secret))
        # Append key and secret to credential-node
        cNode = self.doc.createElement("credentials")
        cNode.appendChild(kNode)
        cNode.appendChild(pNode)
        cNode.appendChild(sNode)
        # Base64-encode credential-node
        cNode = self.doc.createTextNode( base64.b64encode(cNode.toxml()) )
        # Add as credentials as textNode to device's top node
        dNode.appendChild(cNode)
        return dNode

    def addDevice(self, device):
        u"Add device to config"
        if not isinstance(device, DeviceItem):
            raise ValueError()
        oNode = self.getDevice(device.id)
        if oNode:
            oNode.node.parentNode.replaceChild(device.node, oNode.node)
        else:
            try:
                element = self.cfg.getElementsByTagName("devices")[0]
            except IndexError:
                pNode = self.doc.createElement("devices")
                pNode.appendChild(device.node)
                self.cfg.insertBefore(pNode, self.cfg.firstChild)
            else:
                element.appendChild(device.node)
        self.write()
    
    @property
    def devices(self):
        u"Returns devices as a list."
        return [d for d in self.iterDevices()]

    @devices.setter
    def devices(self, iter):
        devices = self.doc.createElement("devices")
        for device in iter:
            devices.appendChild(device.node)
        for pNode in self.cfg.getElementsByTagName("devices"):
            self.cfg.removeChild(pNode)
            #self.cfg.replaceChild(devices,pNode)
            #break
        #else:
        self.cfg.insertBefore(devices, self.cfg.firstChild)
        self.write()

    @devices.deleter
    def devices(self,device):
        # Compare id with all devices in XML
        for dNode in self.cfg.getElementsByTagName(device.id): # "device"
            # Remove device on match
            dNode.parentNode.removeChild(dNode)

    def delDevice(self, id, write = True):
        u"Delete device with a specified ID in loaded document."
        for pNode in self.cfg.childNodes:
            if pNode.tagName == "devices":
                for dNode in pNode.childNodes:
                    if dNode.tagName == id:
                        pNode.removeChild(dNode)
                        if write: self.write()
                        return id
                else:
                    return None
        else:
            return None

    def getDevice(self, id):
        u"Get device with a specified ID from loaded document."
        for pNodes in self.cfg.getElementsByTagName("devices"):
            dNodes = self.cfg.getElementsByTagName(id)
            if dNodes:
                return DeviceItem( dNodes[0] )
            else:
                return None

    def iterDevices(self):
        u"Iterate over all devices in config."
        for devices in self.cfg.getElementsByTagName("devices"):
            for dNode in devices.childNodes:
                yield DeviceItem(dNode)

    def parse(self, path):
        u"Parse document from harddrive."
        with open(path, "r") as f:
            data = f.read()
        return self.parseString(data)

    def parseString(self, s):
        u"Parse document from string."
        # Setup pattern matching newLines and indents between tags
        i = re.compile(">\n( *)<")
        # Sanitize prettyprinted document from pattern
        doc = xml.dom.minidom.parseString(re.sub(i,"><",s))
        # Setup pattern matching newLines and indents inside textNodes
        i = re.compile("\n( *)")
        # Sanitize pretty textNodes that belong to device-Nodes
        pNodes = (p.childNodes for p in doc.getElementsByTagName("devices"))
        for pNode in pNodes:
            for dNode in pNode:
                nNode = doc.createTextNode(re.sub(i, "", dNode.firstChild.data))
                dNode.replaceChild(nNode, dNode.firstChild)
        return doc

    def read(self, path=None, colors=False, currencies=False):
        u"Read config and (re)set dictionaries with new settings."
        if path: self.path = path
        self.doc = self.parse(self.path)
        cfg = self.doc.firstChild
        if cfg.tagName == "GoxCLI":
            self.cfg = cfg
        else:
            raise InputError("Error reading XML")
        for sNode in self.cfg.childNodes:
            if sNode.tagName == "settings":
                #sNode = node
                break
        if currencies:
            self.currencies = self._read_currencies(sNode)
        if colors:
            self.colors = self._read_colors(sNode)

    def _read_colors(self,sNode):
        u"Read colors from document and return settings in a dictionary."
        ansi  = sNode.getElementsByTagName("ansi")[0].childNodes
        ansi  = dict((c.tagName, c.attributes["value"].value) for c in ansi)
        # Human readeable settings (colorNode)
        cNode = sNode.getElementsByTagName("shell")[0]
        # Save a dict with (keys = human readable, values = ansi).
        color = lambda v: (v.tagName, ansi[v.attributes["value"].value])
        return dict(color(v) for v in cNode.childNodes)

    def currency(self, currency):
        u"Read currencies from document and return settings in a dictionary."
        currency = currency.upper()
        if self.currencies:
            try:
                return sorted(self.currencies[currency].itervalues())
            except KeyError:
                raise InputError("Invalid currency:  %s" % currency,
                                kind = "currency", arg = currency)
        for sNode in self.cfg.childNodes:
            if sNode.tagName == "settings":
                break
        else:
            raise InputError("Invalid XML: No settings found",
                              kind = "XML", arg = "No settings found" )
        for cNode in sNode.childNodes:
            if cNode.tagName == "currencies":
                for cNode in cNode.childNodes:
                    if cNode.tagName == currency:
                        break
                else:
                    m = "%s: %s" % ("Currency not found", currency)
                    raise InputError("Invalid XML: " + m, kind = "XML", arg = m)
                prefix   = cNode.attributes["symbol"].value
                decimals = int( cNode.attributes["decimals"].value )
                break
        else:
            raise InputError("Invalid XML: No currency found",
                              kind = "XML", arg = "No currency found")
        return decimals, prefix.decode("utf-8")

    def _read_currencies(self,sNode):
        u"Read currencies from document and return settings in a dictionary."
        cNodes = sNode.getElementsByTagName("currencies")[0].childNodes
        cDict  = dict()
        for cNode in cNodes:
            currency = cNode.tagName
            try:
                prefix   = cNode.attributes["symbol"].value
                decimals = int( cNode.attributes["decimals"].value )
            except IndexError:
                # TODO: Was it really IndexError?
                m = "%s: %s" % ("Malformed currency: ", currency.upper())
                raise InputError("Invalid XML: %s" % m, kind = "XML", arg = m)
            else:
                cDict[currency] = dict(
                    decimals = decimals,
                    prefix = prefix
                    )
        return cDict

    def write(self, path=None, indent=4):
        path = self.path if not None else path
        indent = " " * indent
        # Create fixed indentation for device's textNodes
        si = "".join(("\n",indent * 2))
        li = "".join(("\n",indent * 3))
        # Clone config-element
        doc = xml.dom.minidom.Document()
        doc.appendChild(self.doc.firstChild.cloneNode(True))
        for pNode in doc.getElementsByTagName("devices"):
            for dNode in pNode.childNodes:
                # Split credential-data into lines of 40 characters
                nNode = dNode.firstChild.data
                nNode = [nNode[x:x+40] for x in xrange(0,len(nNode),40)]
                nNode = li.join(nNode)
                nNode = "{0}{1}{2}".format(li, nNode, si)
                nNode =  self.doc.createTextNode(nNode)
                dNode.replaceChild(nNode, dNode.firstChild)
        trails=re.compile(' *\n')
        final = doc.toprettyxml(indent) #.encode('ascii', 'replace')
        final = re.sub(trails,"\n",final)
        with open(path, "w") as f:
            f.write(final.encode("utf-8"))


class DeviceItem(object):
    def __init__(self, *args, **kwargs):
        u"Container holding info about device."
        if len(args) == 1:
            self.__init_fromNode(*args)
        elif len(args) == 3:
            self.__init_fromValues(*args, **kwargs)
        else:
            raise TypeError("takes 2 or 4 arguments (%s given)"
                            % str(len(args)+1))

    def __init_fromNode(self, dNode):
        u"Create a item from existing Minidom-node."
        if isinstance(dNode, xml.dom.minidom.Element):
            self._node = dNode
            self._credentials = None
        else:
            raise TypeError()

    def __init_fromValues(self, name, key, secret, standard="USD", encrypted=0):
        u"Create item from values given."
        # cloneNode will require all nodes to have ownerDocument set.
        doc = xml.dom.minidom.Document()
        # Create a new ID
        id = "d%s" % uuid.uuid4().hex
        # Create top node of device
        dNode = doc.createElement(id)
        dNode.setAttribute("name", name)
        dNode.setAttribute("standard", standard)
        # Create the "encoded textNode"
        # Key-node
        kNode = doc.createElement("key")
        kNode.setAttribute("value", str(key))
        # Listening-node (if AF_UNIX 1/0, if AF_INET Port/0)
        lNode = doc.createElement("port")
        lNode.setAttribute("value", "0")
        # Secret-Node
        sNode = doc.createElement("secret")
        sNode.setAttribute("length", str(encrypted))
        tNode = doc.createTextNode( secret )
        sNode.appendChild(tNode)
        # Append key and secret to credential-node
        cNode = doc.createElement("credentials")
        cNode.appendChild(kNode)
        cNode.appendChild(lNode)
        cNode.appendChild(sNode)
        # Base64-encode credential-node
        tNode = doc.createTextNode( base64.b64encode(cNode.toxml()) )
        # Add as credentials as a textNode to device
        dNode.appendChild(tNode)
        self._node = dNode
        self._credentials = None

    @property
    def _cNode(self):
        u"Read credential-node from node (Base64-encoded string)."
        if not self._credentials:
            cNode = base64.b64decode( self._node.firstChild.data )
            cNode = xml.dom.minidom.parseString( cNode )
            self._credentials = cNode.firstChild
        return self._credentials

    @_cNode.setter
    def _cNode(self,cNode):
        u"Base64-Encode credential-node's Xml-String and append to node."
        text = base64.b64encode( cNode.toxml() )
        tNode = xml.dom.minidom.Document().createTextNode( text )
        if self._node.hasChildNodes():
            self._node.replaceChild(tNode, self._node.firstChild)
        else:
            self._node.appendChild(tNode)
        self._credentials = cNode

    @property
    def id(self):
        u"Read device's id from node."
        return self._node.tagName

    @id.setter
    def id(self,id):
        u"Set device's id in node."
        self._node.tagName = id

    @property
    def name(self):
        u"Read device's name from node."
        return self._node.attributes["name"].value

    @name.setter
    def name(self,name):
        u"Set device's name in node."
        self._node.setAttribute("name", str(name))

    @property
    def node(self):
        u"Return Minidom-node."
        return self._node

    @node.setter
    def node(self,n):
        u"Set new Minidom-node."
        if isinstance(device, xml.dom.minidom.Element):
            self._node = n
            self._credentials = None
        else:
            raise ValueError("DeviceNode must be minidom Element")

    @property
    def key(self):
        u"Read secret from node."
        key = self._cNode.getElementsByTagName("key")[0]
        key = key.attributes.item(0).value
        return key

    @key.setter
    def key(self,key):
        u"Set secret in node."
        kNode = xml.dom.minidom.Document().createElement("key")
        kNode.setAttribute("value", str(key))
        cNode = self._cNode
        cNode.replaceChild(kNode, cNode.getElementsByTagName("key")[0])
        self._cNode = cNode

    @property
    def length(self):
        u"Read-only property, is set with passing pair of secret and" + \
        u" length to secret-property."
        sNode = self._cNode.getElementsByTagName("secret")[0]
        return int(sNode.attributes["length"].value)

    @property
    def listening(self):
        u"Read listening-status in node. 1/0 if system is" \
        u" compatible with AF_UNIX, otherwise it represents the listening port"
        listening = self._cNode.getElementsByTagName("port")[0]
        listening = int(listening.attributes["value"].value)
        return listening

    @listening.setter
    def listening(self,listening):
        u"Set listening-status in node."
        lNode = xml.dom.minidom.Document().createElement("port")
        lNode.setAttribute("value", str(listening))
        cNode = self._cNode
        cNode.replaceChild(lNode, cNode.getElementsByTagName("port")[0])
        self._cNode = cNode

    @property
    def secret(self):
        u"Read secret from node."
        sNode = self._cNode.getElementsByTagName("secret")[0]
        return sNode.firstChild.data

    @secret.setter
    def secret(self,secret,length="0"):
        u"Pass both secret and length as a pair (secret, length) to set"
        u" secret and length or pass only the secret if not using encrypted" + \
        u" secrets."
        doc = Document()
        tNode = doc.createTextNode(secret)
        sNode = doc.createElement("secret")
        sNode.setAttribute("length", str(length))
        sNode.appendChild(tNode)
        cNode = self._cNode
        cNode.replaceChild(sNode, cNode.getElementsByTagName("secret")[0])
        self._cNode = cNode

    @property
    def standard(self):
        u"Read standard currency from node."
        return self._node.attributes["standard"].value

    @standard.setter
    def standard(self,s):
        u"Set standard currency in node."
        self._node.setAttribute("standard", str(s))


class ServiceReader:
    @staticmethod
    def read(device):
        u"Read credentials from service"
        if socket.AF_UNIX:
            # Unix inter-communication socket, supposedly more secure
            host = "/tmp/{0}".format(device.id) # device.id
            s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        else:
            # Create a TCP socket (Fallback/windows)
            host = ("127.0.0.1", device.listening)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(host)
        except socket.error, e:
            raise DaemonError("Could not connect to service.")
        s.send(device.id)
        try:
            # Receive up to 1kB
            data = s.recv(1024)
        except socket.timeout:
            raise DaemonError("Socket timed out when connecting to service.")
        try:
            data = cjson.decode(data)
        except cjson.DecodeError, e:
            print e
            raise DaemonError("Got invalid reply.")
        return data["key"],data["secret"],int(data["counter"])


class LoginDaemon(object):
    def __init__(self, parent):
        u"Background service providing credentials after logging in."
        self.parent = parent

    def kill(self, device):
        u"Kill old background service"
        if socket.AF_UNIX:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            host = "/tmp/{0}".format(device.id)
        else:
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host = ("127.0.0.1", device.listening)
        # Set timeout in seconds
        sock.settimeout(0.5)
        try:
            # Connect to LoginDaemon
            sock.connect(host)
        except socket.error:
            raise DaemonError(u"Could not connect to service.")
        else:
            # Sending random data to kill, any data will do
            sock.send("terminateAndDie")
            try:
                # Receive up to 1kB
                data = sock.recv(1024)
            except socket.timeout,e:
                print "timeout",e
            else:
                if data != "":
                    raise DaemonError(u"Malformed reply.")
                else:
                    return r'{"data": "Terminated.", "result": "success"}'

    def run(self,daemon=False):
        u"Start daemon threads and listen on socket"
        if not all((self.parent._secret, self.parent._key, self.parent.device)):
            raise DaemonError("Credentials not set")
        if socket.AF_UNIX:
            # Unix inter-communication socket, supposedly more secure,
            # Can only listen at one ID per machine, but instead not be accessed
            # by other users than the one that started the service.
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            # TODO: Maybe I should prefix the pids for each user
            host = "/tmp/{0}".format(self.parent.device.id)
            if daemon:
                if os.path.exists(host):
                    raise DaemonError(
                        u"Service allready listening on this ID. If you are" + \
                        u" sure no service is listening, confirm that no"    + \
                        u" other file is blocking and that you have access"  + \
                        u" to %s" % host)
            try:
                os.remove(host)
            except OSError:
                if os.path.exists(host):
                    try:
                        os.unlink(host)
                    except OSError:
                        raise DaemonError(
                            u"Service could not open socket for this ID." + \
                            u" Please confirm that no other file is blocking" +\
                            u" and that you have access to %s" % host
                            )
            listening = 1
        else:
            # TCP socket, windows-machines...
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Pick random port above 1024
            listening = random.randrange(1025,65555)
            # Bind to localhost only
            host = ("127.0.0.1", listening)
        try:
            sock.bind(host)
        except socket.error,e:
            if not socket.AF_UNIX:
                # Bind failed using TCP, try again with other ports
                # (TODO: Catch device busy-errors instead)
                fail = 1
                while fail < 100:
                    listening = random.randrange(1025,65555)
                    host = ("127.0.0.1", listening)
                    try:
                        sock.bind(host)
                    except:
                        fail += 1
                    else:
                        break
                else:
                    raise DaemonError(u"Could not open listening socket.")
            else:
                # TODO: Catch different kinds of errorcodes (like access denied)
                raise DaemonError(u"Could not open listening socket.")
        # Allow only one connection at a time
        sock.listen(1)
        if not daemon:
            self._daemonize(self._listen, sock)
        return listening

    def _daemonize(self, proc, *args):
        # Throw as background job. This is the same as:
        #  if not((os.fork() == 0 and os.fork() == 0)): sys.exit(0)
        if os.fork():
            # Main process
            return
        else:
            # New process
            if not os.fork():
                # Another fork, our background service
                # NOTE: Without this last fork the process die if the user log
                #       out or close the running shell.
                sys.stdin = open(os.devnull, 'r')
                sys.stdout = open(os.devnull, 'w')
                sys.stderr = open(os.devnull, 'w')
                self._listen(*args)
            sys.exit(0)

    def _listen(self, sock):
        running = True
        # Listen for incoming connections
        while running:
            # Wait for a new connection
            connection, address = sock.accept()
            # Recieve data from client
            data = connection.recv(33)
            if data == self.parent.device.id:
                # Credentials requested
                self.parent._counter += 1
                # Return json with credentials
                reply = dict(key=self.parent._key,
                            secret=self.parent._secret,
                            counter=self.parent._counter
                            )
                connection.send(cjson.encode(reply))
            else:
                # Other data recieved, killing service
                connection.send("")
                running = False
            # Job done, close connection before exiting
            connection.close()
        sys.exit(0)

class MtGoxAPI(object):
    def __init__(self, credentials):
        u"Handles requests made to Mt.Gox."
        self._credentials = credentials
        self._url = "https://mtgox.com/api/"
        
    @property
    def credentials(self):
        if hasattr(self._credentials, "__call__"):
            return self._credentials()
        elif hasattr(self, "_secret"):
            self._counter += 1
            return self._key, self._secret, self._counter
        else:
            self._key, self._secret = self._credentials
            self._counter = 0
    
    @credentials.setter
    def credentials(self, *args):
        if len(args) == 1 and hasattr(args[0], "__call__"):
            self._credentials = args[0]
        elif len(args) == 2:
            self._credentials = args
        else:
            raise ValueError("credentials expected 2 items, got %s" % len(args))
    
    def __request_format_auth(self, path, params, api):
        """ Format a POST-request according to the rules set by Mt.Gox. """
        # Format URL
        url = "".join((self._url, str(api), "/", path))
        # Function requires authentication
        key, secret, counter = self.credentials
        # Timestamp*1000+counter to make no more than 1000 requests per second possible
        params["nonce"] = int(time.time()*1000)+counter
        # Format the POST-data
        data = urllib.urlencode(params)
        try:
            # Decode secret
            secret = base64.b64decode(secret)
            # Hmac-sha512-hash secret, postdata and also path since v2
            if api < 2:
                hash = hmac.new(secret, data, hashlib.sha512)
            else:
                hash = hmac.new(secret, path + chr(0) + data, hashlib.sha512)
            # Digest hash as binary and encode with base64
            sign = base64.b64encode(hash.digest())
        except TypeError:
            # Catch exception thrown due to bad key or secret
            raise CredentialError(
                u"Could not sign request due to bad secret or wrong" + \
                u" password. Please try again or request new " + \
                u" credentials by reactivating your application."
                )
        else:
            # Apply the base64-encoded data together with api-key to header
            headers = {
                    "User-Agent":"GoxCLI",
                    "Rest-Key":key,
                    "Rest-Sign":sign
                    }
            req = urllib2.Request(url, data, headers)
        return url, req, data
    
    def __request_format_public(self, path, params, api):
        """ Format a simple GET-request instead of POST. """
        url  = "".join((self._url, str(api), "/", path))
        data = urllib.urlencode(params) if len(params) > 0 else None
        req  = urllib2.Request(url, data)
        return url, req, data
        
    def _request(self, path, api=2, params={}, currency=None, crypto="BTC", auth=True):
        if api > 1:
            # API v2 require paths like money/info or BTCUSD/money/order/add
            path = "".join(("money/", path))
        if api > 0:
            if currency:
                # Some functions in API v1 and later require currency-pairs like BTCUSD
                path = "".join((crypto,currency,"/",path))
            elif api == 1:
                # Other functions in v1 is preceded by the "generic" domain
                path = "".join(("generic/", path))
        if auth:
            # Instanciate a request using POST including sign for authentication
            url, req, data = self.__request_format_auth(path, params, api)
        else:
            # Instanciate a request using GET
            url, req, data = self.__request_format_public(path, params, api)
        timeout = 15
        try:
            with closing(urllib2.urlopen(req, data, timeout)) as response:
                return response.read()
        except SSLError, e:
            raise MtGoxError("Could not reach Mt.Gox. Operation timed out.")
        except urllib2.HTTPError, e:
            if e.code == 403:
                raise MtGoxError("Authorization to this API denied")
            else:
                raise urllib2.HTTPError(e.url, e.code, e.msg, None, None)
    
    def activate(self,actkey,dName,pw=None):
        u"Activate application and add device to config. You will need at" \
        u" least some rights to use most of the functions in this application."
        rel_path = "api/activate"
        appkey = "52915cb8-4d97-4115-a43a-393c407143ae"
        params = {
                u"name": dName,
                u"key": actkey,
                u"app": appkey
                }
        return self._request(rel_path, params=params, auth=False)

    def add_order(self, kind, amount, price, currency):
        rel_path = "order/add"
        params = {
                "amount_int":str(amount),
                "price_int":str(price),
                "type":kind
                }
        return self._request(rel_path, params=params, currency=currency, auth=True)

    def block(self,hash=None,depth=None):
        u"Retrieve information about a block in bitcoin's blockchain," \
        u" at least one of the arguments hash and number must be defined."
        rel_path = "bitcoin/block_list_tx"
        if hash:
            params = dict(hash=hash)
        elif depth:
            params = dict(depth=depth)
        else:
            params = dict()
        return self._request(rel_path, params=params, auth=False)

    def btcaddress(self,hash):
        u"Requests information about a specific BTC-address."
        rel_path = "bitcoin/addr_details"
        params = {"hash":hash}
        return self._request(rel_path, params=params, auth=False)
    
    def cancel(self, oid):
        u"Cancel order identified with type and oid"
        rel_path = "order/cancel"
        params = { "oid":oid }
        return self._request(rel_path, params=params, auth=True)
        
    def deposit(self):
        u"Requests address for depositing BTC to your wallet at Mt.Gox."
        rel_path = "bitcoin/address"
        return self._request(rel_path, auth=True)
        
    def depth(self, currency=None,full=False):
        u"Request current depth-table at Mt.Gox (aka order book)."
        if full:
            rel_path = "depth/full"
        else:
            rel_path = "depth/fetch"
        return self._request(rel_path, currency = currency, auth = False)

    def history(self, currency, page = 1):
        u"Request wallet history. The history of your BTC-wallet will be" \
        " requested if no currency is defined."
        rel_path = "wallet/history"
        params   = {"currency":currency,"page":page}
        return self._request(rel_path, params = params, auth = True)

    def info(self):
        u"Retrieve private info from Mt.Gox"
        rel_path = "info"
        return self._request(rel_path, auth = True)

    def lag(self):
        u"Returns the time MtGox takes to process each order." \
        u" If this value is too high, trades will be delayed and depth-table" \
        u" will probably not be reliable."
        rel_path = "order/lag"
        return self._request(rel_path, auth = False)
        
    def orders(self):
        u"Requests your open, invalid or pending orders."
        rel_path = "orders"
        return self._request(rel_path, auth = True)
    
    def status(self, type, oid):
        u"Returns trades that have matched the order specified, result will" \
        u" be empty if order still is intact."
        rel_path = "order/result"
        params = dict(type = type, order = oid)
        return self._request(rel_path, params=params, auth=True)

    def ticker(self,currency="USD"):
        u"Request latest ticker from Mt.Gox."
        rel_path = "ticker"
        return self._request(rel_path, currency=currency, auth=False)

    def trades(self,currency="USD",since=None):
        u"Requests a list of successfull trades from Mt.Gox, returns a" \
        u" maximum of one hundred orders."
        rel_path = "trades"
        p = {"since":since} if since else {}
        return self._request(rel_path, currency=currency, params=p, auth=False)

    def transaction(self, hash):
        u"Request information about a transaction within the BTC blockchain."
        rel_path = "bitcoin/tx_details"
        params   = {"hash":hash}
        return self._request(rel_path, params=params, auth=False)
    
    def withdraw(self, destination, amount, fee=Decimal("0.0")):
        u"Withdraw crypto."
        cryptoPrec = Decimal("0.00000001")
        amount_int = int(amount / cryptoPrec)
        fee        = int(fee    / cryptoPrec)
        rel_path   = "bitcoin/send_simple"
        params     = {"address": destination, "amount_int": amount_int }
        if fee: params["fee_int"] = fee
        return self._request(rel_path, params=params, auth=True)


class DepthParser(object):
    def __init__(self, currencyDecimals, args = []):
        self._cPrec = Decimal(1) / 10 ** currencyDecimals
        self.__sides = ("asks","bids")
        try:
            for arg,value in (arg.split("=") for arg in args):
                arg = arg.lower()
                if hasattr(self, arg):
                    try:
                        setattr(self, arg, value)
                    except InvalidOperation:
                        raise InputError( "Invalid value: %s" % value,
                                          kind = "value", arg = value )
                    except ValueError:
                        raise InputError( "Invalid value: %s" % value,
                                          kind = "value", arg = value )
                else:
                    raise InputError("Invalid argument: %s" % arg, arg = arg)
        except ValueError:
            raise InputError("Invalid argument")
            
    @property
    def side(self):
        try:
            return self._side
        except AttributeError:
            return None

    @side.setter
    def side(self,value):
        if value:
            if value == "bids":
                self._side = value
                self.__sides = ("bids",)
            elif value == "asks":
                self._side = value
                self.__sides = ("asks",)
            else:
                raise InputError( "Invalid value : %s" % value,
                                   kind = "value", arg = value )
        else:
            self._side = None
            self.__sides = ("asks","bids")

    @property
    def low(self):
        try:
            return self._minPrice
        except AttributeError:
            return None

    @low.setter
    def low(self, value):
        if value:
            self._minPrice = Decimal(value)
        else:
            self._minPrice = None

    @property
    def high(self):
        try:
            return self._maxPrice
        except AttributeError:
            return None

    @high.setter
    def high(self, value):
        if value:
            self._maxPrice = Decimal(value)
        else:
            self._maxPrice = None

    @property
    def amount(self):
        try:
            return self._maxAmount
        except AttributeError:
            return None

    @amount.setter
    def amount(self, value):
        if value:
            self._maxAmount = Decimal(value)
        else:
            self._maxAmount = None
        
    @property
    def value(self):
        try:
            return self._maxValue
        except AttributeError:
            return None

    @value.setter
    def value(self, value):
        if value:
            self._maxValue = Decimal(value)
        else:
            self._maxValue = None
        
    @property
    def steps(self):
        try:
            return self._steps
        except AttributeError:
            return None

    @steps.setter
    def steps(self, value):
        if value:
            self._steps = int(value)
        else:
            self._steps = False
        
    @property
    def iv(self):
        try:
            return self._iv
        except AttributeError:
            return False

    @iv.setter
    def iv(self, value):
        self._iv = self.readBool(value)
        
    @property
    def full(self):
        try:
            return self._full
        except AttributeError:
            return False

    @full.setter
    def full(self, value):
        self._full = self.readBool(value)

    @property
    def cumulate(self):
        try:
            return self._cumulate
        except AttributeError:
            return False

    @cumulate.setter
    def cumulate(self, value):
        self._cumulate = self.readBool(value)
            
    def readBool(self, value):
        if value:
            if isinstance(value, str):
                try:
                    value = {"true":True,"false":False}[value.lower()]
                except KeyError:
                    raise InputError( "Invalid value : %s" % value,
                                       kind = "value", arg = value )
            return bool(value)
        else:
            return False
        
        
    def process(self, json, raw = True):
        u"Parse depth-table from Mt.Gox, returning orders matching arguments"
        # Check if user has applied any arguments so we need to parse and strip the json
        json      = JsonParser.parse(json)["data"]
        steps     = self.steps
        oMinPrice = self.low
        oMaxPrice = self.high
        maxAmount = self.amount
        maxValue  = self.value
        cumulate  = self.cumulate
        iv        = self.iv
        # Get the decimal precision for currency
        cPrec    = self._cPrec
        bPrec    = Decimal("0.00000001")
        # Setup empty table
        gen      = (i for i in json.iteritems() if i[0] not in ("asks","bids"))
        table    = dict(( (key, value) for key, value in gen ))
        if maxAmount: maxAmount = int(maxAmount / bPrec)
        if maxValue:  maxValue  = int(maxValue / cPrec / bPrec)
        if self.side:
            if self.side == "asks":
                table["bids"] = []
            else:
                table["asks"] = []
        else:
            table["gap"] = dict()
            table["gap"]["upper"]     = json["asks"][0]["price"]
            table["gap"]["upper_int"] = json["asks"][0]["price_int"]
            table["gap"]["lower"]     = json["bids"][-1]["price"]
            table["gap"]["lower_int"] = json["bids"][-1]["price_int"]
        for side in self.__sides:
            # Parse sides independently
            orders = json[side]
            # Read lowest and highest price of orders on current side
            lowest  = int(orders[0][u"price_int"])
            highest = int(orders[-1][u"price_int"])
            # Convert minimum and maximum price from arguments to int
            #  and check if any orders are within that range.
            if oMinPrice == None: minPrice = None
            else:
                minPrice = int(oMinPrice / cPrec)
                if minPrice > highest:
                    # Argument input totally out of range, return empty
                    table[side] = []
                    continue
                elif minPrice < lowest:
                    # Adjust argument to range
                    minPrice = lowest
            if oMaxPrice == None: maxPrice = None
            else:
                maxPrice = int(oMaxPrice / cPrec)
                if maxPrice < lowest:
                    # Argument input totally out of range, return empty
                    table[side] = []
                    continue
                elif maxPrice > highest:
                    # Adjust argument to range
                    maxPrice = highest
            # Check wether argument input is within the range of
            # the table returned from Mt.Gox.
            if any(( steps,
                     minPrice,
                     maxPrice,
                     maxAmount,
                     maxValue,
                     cumulate,
                     iv )):
                if any((minPrice, maxPrice)):
                    # Get generator yielding orders within given pricerange.
                    if minPrice == None: minPrice = lowest
                    if maxPrice == None: maxPrice = highest
                    orders = self._stripRange(
                        orders,
                        side,
                        minPrice,
                        maxPrice
                        )
                if any((maxAmount, maxValue)):
                    # Filter orders from price and out, only keeping those
                    #  that have either lower value or amount (cumulated).
                    orders = self._processList(
                        orders, side,
                        precision = cPrec,
                        cumulate  = False if steps else cumulate,
                        maxAmount = maxAmount,
                        maxValue  = maxValue,
                        iv        = False if steps else iv
                        )
                elif not steps and any((iv, cumulate)):
                    # If no other option is set except possibly min-/maxPrice,
                    #  add value-item to orders and/or cumulate list.
                    orders = self._processList(
                        orders, side,
                        precision = cPrec,
                        cumulate  = cumulate,
                        iv        = iv
                        )
                if steps:
                    if any((maxAmount, maxValue, minPrice, maxPrice)) and orders:
                        # Slice list into <steps> slices and then merge
                        #  them into one order per slice.
                        if any((maxAmount, maxValue)):
                            if side == "asks":
                                min = int( orders[0]["price_int"])
                                max = int(orders[-1]["price_int"])
                            else:
                                min = int(orders[-1]["price_int"])
                                max = int( orders[0]["price_int"])
                        else:
                            min = minPrice
                            max = maxPrice
                        orders = self._stepList(
                            orders, side,
                            min, max
                            )
                        # Flip back orderlist and resturn
                        if side == "bids":
                            try:
                                # Reverse list from processList
                                orders = reversed(orders)
                            except TypeError:
                                # Reverse generator from stripRange
                                orders = list(orders)
                                orders.reverse()
                    else:
                        # Grab speciefied amount of orders closest to price.
                        if side == "asks":
                            orders = orders[:steps]
                        else:
                            orders = orders[steps*-1:]
                        if cumulate or iv:
                            # Iterate and sum previous orders
                            orders = self._processList(
                                orders, side,
                                precision = cPrec,
                                cumulate  = cumulate,
                                iv        = iv
                                )
                            # Flip back orderlist and resturn
                            if side == "bids": orders = reversed(orders)
                else:
                    # Flip back orderlist and resturn
                    if not isinstance(orders, list): orders = list(orders)
                    if side == "bids": orders = reversed(orders)
            table[side] = list(orders)
        json = {
                "data":table,
                "result":"success"
                }
        return JsonParser.build(json) if raw else json

    def _stepItemList(self, items, steps, kind="trades"):
        u"Old stepList, but will work to step trades instead when creating" \
        u" RSI and stuff."
        if not hasattr(orders, "__delslice__"):
            # Convert generator or tuple to lists, assume all objects that have
            #  __delslice__ also has __getitem__ and __getslice__
            orders = list(orders)
        subs = list()
        length = len(orders)
        # Calculate size of step and then adjust to whole integer
        # Round to make sure no orders 
        step = round( float(length) / steps ) * steps
        if length/steps * steps >= length:
            stepSize = length / teps
        else:
            stepSize = length/steps+1
        while orders:
            # Take slices of orderlist in stepsize
            subs.append(orders[0:stepSize])
            del orders[0:stepSize]
        else:
            if not self.cumulate:
                for step in subs:
                    # Merge each slice of list to one order
                    proc = self.getattr("_merge_{0}".format(kind))(*args)
                    step = self._processList(
                        step, side,
                        precision = self._cPrec,
                        cumulate  = True,
                        iv        = iv
                        )
                    # Last order contains amount and value of earlier orders
                    step          = step[-1]
                    step["stamp"] = str(self.latestStamp)
                    orders.append(step)
            else:
                # Merge each slice of list to one order while cumulating the
                #  last layer being created
                totalA = 0
                totalV = 0
                for step in subs:
                    step = self._processList(
                        step, side,
                        precision = self._cPrec,
                        cumulate  = True,
                        iv        = iv
                        )
                    order   = step[-1]
                    totalA  += int(order["amount_int"])
                    totalV  += int(order["value_int"])
                    # Cumulate orders
                    order = self._manipulateOrder(
                        order,
                        amount_int = totalA,
                        precision  = self._cPrec,
                        iv         = totalV
                        )
                    orders.append(order)
            return orders if side == "ask" else reversed(orders)

    def _stepList(self, orders, side, min, max):
        u"Slice a big list of orders and merge each slice to one order," + \
        u" lists of bids needs to be reversed when passed as argument."
        stepList = list()
        if side == "asks":
            stepSize = (max - min) / self.steps
            # Price increases for each ask
            stepEnd = min + stepSize
            withinStep = lambda orderPrice: orderPrice <= stepEnd
        else:
            # Reverse if not allready done (roughly tuple/list, not generator)
            if hasattr(orders, "__getitem__"):
                if orders[-1] < orders[0]:
                    orders = reversed(orders)
            # Price decreases for each bid
            stepSize = (max - min) * -1 / self.steps
            withinStep = lambda orderPrice: orderPrice >= stepEnd
            stepEnd = max + stepSize
        if self.iv:
            # Values included in orders
            calcStep = lambda amount, orderAmount, orderPrice, value: \
                ( amount + orderAmount , value + (orderAmount * orderPrice) )
        else:
            # Don't include value
            calcStep = lambda amount, orderAmount, orderPrice, value: \
                ( amount + orderAmount, False )
        amount,value,stamp = 0,0,0
        for order in orders:
            orderPrice  = int(order["price_int"])
            orderAmount = int(order["amount_int"])
            orderStamp  = int(order["stamp"])
            if withinStep(orderPrice):
                # Return total amount and value of step
                amount, value = calcStep(amount, orderAmount, orderPrice, value)
                price         = orderPrice
                # Replace stamp if this one is newer
                if stamp < orderStamp: stamp = orderStamp
            else:
                stepList.append(
                    self._manipulateOrder(
                        dict(),
                        price_int  = price,
                        amount_int = amount,
                        stamp      = stamp,
                        precision  = self._cPrec,
                        iv         = value
                        )
                    )
                # Set Amount,Value,Stamp to this order's values
                if not self.cumulate:
                    amount, value = calcStep(0, orderAmount, orderPrice, 0)
                stamp = orderStamp
                # Set next step end
                stepEnd += stepSize
        else:
            if withinStep(price):
                # Add step if orders has been parsed since last step was added
                stepList.append(
                    self._manipulateOrder(
                        dict(),
                        price_int  = price,
                        amount_int = amount,
                        stamp      = stamp,
                        precision  = self._cPrec,
                        iv         = value
                        )
                    )
        return stepList

    def _stripRange(self, orders, side, minPrice, maxPrice):
        u"Strip list of all orders outside of the range between minPrice" + \
        u" and maxPrice. All generator-objects is treated like they're"   + \
        u" allready reversed when parsing bids."
        if side == "asks":
            # Allow all orders above minPrice
            withinRange = lambda price: int(price) >= minPrice
            # Break when iteration has reached order above maxPrice
            breakPoint  = lambda price: int(price) >  maxPrice
        else:
            if hasattr(orders, "__getitem__"):
                if orders[-1] < orders[0]:
                    orders = reversed(orders)
            # Allow all orders below maxPrice
            withinRange = lambda price: int(price) <= maxPrice
            # Break when iteration has reached order below minPrice
            breakPoint  = lambda price: int(price) <  minPrice
        # Iterate over list,
        #  Asks: Low  -> High
        #  Bids: High -> Low
        for order in orders:
            if withinRange(order[u"price_int"]):
                if breakPoint(order[u"price_int"]):
                    break
                else:
                    yield order

    def _processList(self,
            orders, side,
            cumulate  = False,
            precision = None,
            maxAmount = False,
            maxValue  = False,
            iv        = False):
        u"Iterates over orders. Adds value and/or cumulate amounts. If list" + \
        u" is a generator it is bids being parsed the generator needs to"    + \
        u" contain a reversed list."
        latestStamp = 0
        totalA  = 0
        totalV  = 0
        current = []
        # Reverse bid-orders if not allready done or if object is a generator.
        if side == "bids" and hasattr(orders, "__getitem__"):
            if orders[1] < orders[0]:
                orders = reversed(orders)
        # Set up lambdas to get rid of some code when iterating over orders.
        if iv:
            # Generated orders will Include Values, ->
            if cumulate:
                # -> and also be cumulated.
                lambda_add = lambda order, amount, totalA, value, totalV: \
                    self._manipulateOrder(
                        order,
                        amount_int = totalA,
                        precision  = precision,
                        iv         = totalV
                        )
            else:
                # -> but will not be cumulated.
                lambda_add = lambda order, amount, totalA, value, totalV: \
                    self._manipulateOrder(
                        order,
                        amount_int = amount,
                        precision  = precision,
                        iv         = value
                        )
        else:
            # Generated orders will not include values, ->
            if cumulate:
                # -> but will be cumulated.
                lambda_add = lambda order, amount, totalA, value, totalV: \
                    self._manipulateOrder(
                        order,
                        amount_int = totalA,
                        precision  = precision
                        )
            else:
                # -> neither will they be cumulated.
                lambda_add = lambda order, amount, totalA, value, totalV: \
                    self._manipulateOrder(
                        order,
                        amount_int = amount,
                        precision  = precision
                        )
        for order in orders:
            # Read each order, decrementing by price if bids
            if maxAmount and totalA > maxAmount: break
            if maxValue and totalV > maxValue: break
            amount = int(order[u"amount_int"])
            price  = int(order[u"price_int"])
            stamp  = int(order[u"stamp"])
            value   = amount * price
            # Increase total amount and total value in currency
            totalA += amount
            totalV += value
            if stamp < latestStamp:
                latestStamp = stamp
            # Generate new order and append to (current) orders
            order   = lambda_add(order, amount, totalA, value, totalV)
            current.append(order)
        self.latestStamp = latestStamp
        return current

    def _manipulateOrder(self, order,
            price_int  = False,
            amount_int = False,
            stamp      = False,
            precision  = False,
            iv         = False):
        u"Update existing order with new data such as price, amount or value."
        bPrec = Decimal("0.00000001")
        if not any([price_int, amount_int, stamp, precision, iv]):
            return order
        if price_int:
            # Converting price integer to decimal with proper length
            if precision:
                # Converting amount integer to decimal with proper length
                price = Decimal(price_int) * precision
                price = price.quantize(precision)
                # Saving as float for cjson encoding
                order["price"]     = float(price)
                order["price_int"] = price_int
            else:
                raise AttributeError("precision")
        if amount_int:
            # Converting amount integer to decimal with proper length
            amount = Decimal(amount_int) * bPrec
            amount = amount.quantize(bPrec)
            # Saving as float for cjson encoding
            order["amount"]     = float(amount)
            order["amount_int"] = str(amount_int)
        if stamp:
            # Replacing stamp
            order["stamp"] = str(stamp)
        if iv:
            # Adds BTC value in currency to result
            value = iv * precision * bPrec
            value = value.quantize(precision)
            order["value"]     = float(value)
            order["value_int"] = int(iv)
        return order

class ActionHandler(object):
    def __init__(self):
        u"Handles arguments and additionally calls appropriate request and" \
        u"parser of result."
        self.api       = MtGoxAPI(self.credentials)
        self.xml       = XmlParse("goxcli.xml")
        self.device    = None
        self.user      = None
        self._standard = None
        self._key      = None
        self._secret   = None
        self._counter  = 0

    def credentials(self):
        if not all((self._key, self._secret)):
            if not self.device:
                if self.opts.id:
                    device = self.xml.getDevice(self.opts.id)
                else:
                    try:
                        device = self.xml.devices[0]
                    except IndexError:
                        raise CredentialError(
                            u"No device found in config, you must activate your" + \
                            u"application to use this function.")
            else:
                device = self.device
            # if device.length - if secret is encrypted
            if device.length:
                if device.listening:
                    data = ServiceReader.read(device)
                    self.device = device
                    self._key, self._secret, self._counter = data
                else:
                    raise CredentialError("Service is not listening on this ID.")
            else:
                self.device = device
                self._key, self._secret = device.key, device.secret
                self._counter += 1
        else:
            self._counter += 1
        return self._key, self._secret, self._counter

    def set_credentials(self, device, secret):
        u"Set all variables needed and test them."
        self.device    = device
        self._key      = device.key
        self._standard = device.standard
        self._secret   = secret
        self._counter  = 0
        self.api.standard = device.standard
        try:
            json = JsonParser.parse(self.api.info())
        except MtGoxError, e:
            self.user      = None
            self.device    = None
            self._standard = None
            self._key      = None
            self._secret   = None
            self._counter  = 0
        else:
            self.user   = json["data"]["Login"]

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
                    # Take first device in config, but only if it's the only
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

    def __cmd_name(self, attr, exp):
        match = re.match(exp, attr)
        return match.group(1) if match != None else None

    def action(self, opts, args):
        u"Take first argument and launch appropriate function"
        try:
            action = args.pop(0)
        except IndexError:
            raise InputError("Input did not contain any action", kind="action", arg=None)
        try:
            proc = getattr(self, "_action_{0}".format(action))
        except CredentialError, e:
            return JsonParser.build(dict(error=e))
        except AttributeError,e:
            raise InputError("Invalid action: %s" % action, kind="action", arg=action)
        except InvalidOperation, e:
            v = e.message.rpartition(" ")[2].lstrip("u\'").rstrip("'")
            raise InputError("Invalid value: %s " % v, kind="value", arg=v)
        else:
            return proc(opts,args)

    def _action_activate(self,opts,args):
        u"activate <activation-key>\n"\
        u"<activation-key> This key is retrieved from Security Center at" \
                        u" Mt.Gox under the tab \"Application Access\".\n" \
        u"NOTE: You can run this more than once to use multiple devices."
        
        pw = str()
        if not len(args):
            # Activation-key is missing, cannot activate
            raise InputError("Missing key for activation, you can get one in"\
                             "security center at MtGox.com")
        # Retrieve devicename
        devices = self.xml.devices
        if len(self.xml.devices) == 1:
            dName = devices[0].name
        else:
            # Assign prefix + random string
            dName = "GoxCLI_"
            dName += "".join(random.choice(string.ascii_uppercase + string.digits) for x in range(10))
        # Get user inputs
        pw, dName = self._interactive_activate(dName=dName)
        # Call API
        json = self.api.activate(args[0], dName)
        # Parse data
        json = JsonParser.parse(json)
        data = json["data"]
        key  = data[u"Rest-Key"].decode('string_escape')
        self._secret = data[u"Secret"].decode('string_escape')
        if pw:
            # Encrypt secret
            length = len(self._secret)
            # Setup SHA256-hash
            hash     = SHA256.new()                             
            # Hash password
            hash.update(pw)                                 
            # base64-encode password
            password = binascii.b2a_base64(hash.digest())   
            # Truncating hash to get a valid length
            password = password[0:32]                       
            # Set password to encrypt secret with
            aes      = AES.new(password, AES.MODE_ECB)           
            # Fill secret with leading zeros to get a valid length
            secret   = str.zfill(self._secret, 128)     
            # AES-encrypt secret
            secret   = aes.encrypt(secret)        
            # binary->base64-encoded secret
            secret   = binascii.b2a_base64(secret)
        else:
            secret = self._secret
            length = 0
        rights = dict()
        for dkey in ("get_info","trade","deposit","withdraw","merchant"):
            rights[dkey] = True if data[u"Rights"].get(key,False) else False
        # Save values to config
        device = DeviceItem(dName, key, secret, encrypted=length)
        id     = device.id
        self.xml.addDevice(device)
        json = {
                "data":{"name":dName,"id":id,"rights":rights},
                "result":"success"
                }
        return JsonParser.build(json)

    def _interactive_activate(self, dName=None):
        u"Input class for interfaces to override, return standard device name"+\
        u" as well as blank password which disables encryption."
        password = None
        return password, dName

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
        return self.api.block(hash=hash,depth=depth)

    def _action_btcaddress(self,opts, args):
        u"btcaddress <address>\n" \
        u"<address> The address to look up, not formatted as normal addresses" \
        u" and have not been able to recieve any information on the subject" \
        u" from Mt.Gox who otherwise has been really helpful. If you find out" \
        u" how to format these addresses, please send me an e-mail."
        if not len(args):
            raise InputError("Not enough arguments.")
        return self.api.btcaddress(args[0])

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
        return self._addorder(opts, args, "ask")

    def _addorder(self, opts, args, kind):
        u"Internal function to post orders at Mt.Gox,\n" \
        u"called by sell- and buy-action."
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
            if opts.asbtc:
                # "If user applied amount in BTC", convert amount to int
                amount = amount / bPrec
            else:
                # Convert amount specified in currency (value) to BTC
                amount = amount / price
                # Convert amount to int
                amount = amount / bPrec
            # Convert price to int
            price = price / cPrec
        else:
            # Generate order with a certain amount or value
            side   = "bids" if kind == "ask" else "asks"
            json   = self.api.depth(currency)
            depth  = DepthParser(decimals)
            depth.side   = side
            if opts.asbtc:
                # Convert amount to to int
                amount = amount / bPrec
                # Get price
                depth.steps  = 1
                depth.amount = amount
                json         = depth.process(json, raw = False)
                price        = int(json["data"][side][0]["price_int"])
            else:
                # Amount given in currency-value.
                depth.value = amount
                depth.iv    = True
                # Convert value to to int
                total = amount / cPrec
                total = total  / bPrec
                # Get price and amount
                orders  = depth.process(json, raw = False)["data"][side]
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
        amount, price = str(amount), str(price)
        return self.api.add_order(kind, amount, price, currency)
    
    def _action_cancel(self, opts, args):
        u"cancel <oid>\n" \
        u"<oid> OrderID of the order."
        if len(args) != 1:
            raise InputError("Expected 1 argument, got %s" % len(args))
        else:
            return self.api.cancel(args[0])

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
                     "data": returns }
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
                     "data": returns }
        return JsonParser.build(json)

    def _action_deposit(self, opts, args):
        u"deposit"
        return self.api.deposit()

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
        if args:
            if len(args) == 1 and args[0].lower() == "full=true":
                full = True
            else:
                # Need to process list with DepthParse-class
                decimals = self.xml.currency(currency)[0]
                depth = DepthParser(decimals, args = args)                
                json  = self.api.depth(
                    currency = currency,
                    full     = depth.full
                    )
                return depth.process(json)
        else:
            full = False
        return self.api.depth(
            currency = currency,
            full     = full
            )

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
        return self.api.history(currency = currency, page = page)

    def _action_info(self, opts, args):
        u"info"
        return self.api.info()

    def _action_lag(self, opts, args):
        u"lag"
        return self.api.lag()

    def _action_orders(self, opts, args):
        u"orders"
        return self.api.orders()

    def _action_status(self, opts, args):
        u"status <type> <oid>\n" \
        u"<type> Order type, could be either ask or bid.\n" \
        u"<oid> OrderID of the order."
        if len(args) == 2:
            type,oid = args
        else:
            raise InputError("Expected 2 argument, got %s" % len(args))
        return self.api.status(type,oid)
        
    def _action_ticker(self, opts, args):
        u"ticker"
        currency = opts.currency.upper() if opts.currency else self.standard
        return self.api.ticker(currency=currency)

    def _action_trades(self, opts, args):
        u"trades [since=int]\n" \
        u"[since=int] Returns trades made after trade with TradeID <int>.\n"
        currency = opts.currency.upper() if opts.currency else self.standard
        since = None
        for arg in args:
            # Split key-word arguments
            try:
                key,value = arg.split("=")
                key = key.lower()
            except ValueError:
                raise InputError("Invalid argument: " + arg, arg=arg)
            else:
                # Parse key-word arguments
                if key == "since":
                    try:
                        since = int(value)
                    except ValueError:
                        raise InputError("Invalid value: " + value,
                                         kind="value", arg=value)
                else:
                    raise InputError("Invalid argument: " + arg, arg=arg)
        return self.api.trades(currency=currency,since=since)

    def _action_transaction(self, opts, args):
        u"transaction <hash=str>\n" \
        u"<hash=str> Hash of the transaction you want to request information" \
        u" about."
        if len(args) == 1:
            return self.api.transaction(args[0])
        else:
            raise InputError("Expected 1 argument, got %s" % len(args))
    
    def _action_withdraw(self, opts, args):
        u"withdraw <destination> <amount> <fee=dec>\n" \
        u"<destination> Destination address.\n" \
        u"<amount> Amount to withdraw.\n" \
        u"<fee=dec> Amount to pay out in fees (Max 0.1).\n"
        if len(args) < 2:
            raise InputError("Expected 2 or 3 arguments, got %s" % len(args))
        destination, amount = args.pop(0), args.pop(0)
        try:
            amount = Decimal( amount )
        except InvalidOperation:
            raise InputError("Invalid argument: '%s'" % amount )
        if args:
            try:
                k,v = args[0].split("=")
            except ValueError:
                raise InputError("Invalid argument: " + arg, arg=arg)
            else:
                if k.lower() == "fee":
                    fee = Decimal(v)
                else:
                    raise InputError("Invalid argument: %s" % k, arg=k)
        else:
            fee = Decimal("0.0")
        return self.api.withdraw(destination, amount, fee)
    
    def login(self):
        devices = self.xml.devices
        if self.opts.id:
            device = self.xml.getDevice(self.opts.id)
            if not self.xml.getDevice(self.opts.id):
                raise InputError("Invalid id")
        elif devices:
            if len(devices) > 1:
                device = self._interactive_device(devices)
            else:
                device = devices[0]
        else:
            raise CredentialError(
                "No devices found in config, you must activate " \
                "your application before you can login."
            )    
        if device.length:
            # Prompt user to provide password to decrypt secret
            pw = self._interactive_pw()
            # Hash password
            hash = SHA256.new()
            hash.update(pw)
            # Base64-encode password and truncate to valid password-length
            pw = binascii.b2a_base64(hash.digest())
            pw = pw[0:32]
            # Prepare AES with password
            aes = AES.new(pw, AES.MODE_ECB)
            # Convert secret to binary (From base64)
            secret = binascii.a2b_base64(device.secret)
            # Actual decryption
            secret = aes.decrypt(secret)
            # Count and truncate leading zeros
            length = str(128-device.length)
            secret = re.sub(r"\b0{"+str(length)+"}","",secret)
        else:
            secret = device.secret
        return device, secret

    def killService(self, device=None):
        if device:
            return LoginDaemon(self).kill(device)
        else:
            result,returns = "success",list()
            for device in self.xml.devices:
                if device.listening:
                    try:
                        returns.append(LoginDaemon(self).kill(device))
                    except DaemonError, e:
                        result = "error"
                        error = {"id":device.id,"message":str(e)}
                        returns.append({"result":u"error",u"error":error})
                    else:
                        device.listening = 0
                        self.xml.addDevice(device)
            return JsonParser.build({"result":result, "data":returns})

    def runService(self,daemon=False):
        self.set_credentials(*self.login())
        if self.device.secret == self._secret:
            raise DaemonError("Daemon not needed for devices with unencrypted" + \
                              "secrets.")
        json = self.api.info()
        json = JsonParser.parse(json)
        if u"error" in json:
            raise CredentialError(u"Could not log in. Please reactivate " + \
                                  u"your application.")
        else:
            acc = json["data"]["Login"]
            listening = LoginDaemon(self).run(daemon=daemon)
            self.device.listening = listening
            self.xml.addDevice(self.device)
            json = {
                "account": acc,
                "id":      self.device.id,
                "name":    self.device.name
                }
            json = {"result":"success", "data":json}
            return JsonParser.build(json)
        
    #def _action_add_wallet(self, opts, args):
    #    u"Redeems your private key inside your wallet.dat"
    #
    #def _action_add_private(self, opts, args):
    #    u"Redeem private key"
    #
        
class OptObject(object):
    def __init__(self,
        opts     = None,
        currency = "USD",
        raw      = False,
        asbtc    = True,
        pretty   = True,
        daemon   = False,
        xml      = "goxcli.xml",
        id       = None):
        if opts:
            self.currency = str(opts.currency)
            self.raw      = bool(opts.raw)
            self.asbtc    = bool(opts.asbtc)
            self.daemon   = bool(opts.daemon)
            self.xml      = str(opts.xml)
            self.id       = id
        else:
            self.currency = currency
            self.raw      = raw
            self.asbtc    = asbtc
            self.daemon   = daemon
            self.xml      = xml
            self.id       = id


class ShellHandler(ActionHandler):
    def setup(self,encoding):
        self.opts   = OptObject()
        self.xml.read(self.opts.xml, colors = True, currencies = True)
        self.creset = self.xml.colors.get("reset", "\033[0;0m")
        self.creset = self.creset.decode("string_escape")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.__complete)
        self.__time_diff = None
        regexp = ur"^\{0}(\d*\.?\d+)$|^(\d*\.?\d+)\{0}$"
        self._re_compile = lambda c: \
            re.compile(
                regexp.format(
                    self.xml.currencies[c]["prefix"]
                )
            )
        gen = ((c,self._re_compile(c)) for c in self.xml.currencies.iterkeys())
        self.re_sign       = dict( gen )
        self.__encoding    = encoding
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

    def colorText(self, text, colorName, reset = True):
        u"Returns a string containing colored text."
        color = self.xml.colors.get(colorName, "\033[0;0m").decode("string_escape")
        color = color.decode("string_escape")
        reset = self.creset if reset else ""
        return u"{color}{text}{reset}".format(color = color,
                                              text  = text,
                                              reset = reset)

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

    def run(self):
        u"Run shell-variant of GoxCLI."
        # Read in config file
        device = None
        if self.xml.devices:
            device = self.xml.devices[0]
            if device.length == 0:
                secret = device.secret
            else:
                try:
                    secret = ServiceReader.read(device)[1]
                except DaemonError:
                    pass
        if device:
            self.api.standard = device.standard
            try:
                json = self._action_info(self.opts, None)
            except CredentialError: pass
            except MtGoxError:
                print self.colorText("Mt.Gox rejected credentials","shell_self")
                self.api = MtGoxAPI(self.credentials)
            except urllib2.HTTPError, e:
                print self.colorText("Could not login: \"%s\"" % e,"shell_self")
                self.api = MtGoxAPI(self.credentials)
            except urllib2.URLError, e:
                print self.colorText("Could not login: \"%s\"" % e,"shell_self")
                self.api = MtGoxAPI(self.credentials)
            except DaemonError:
                pass
            else:
                json = JsonParser.parse(json)
                if u"error" in json.iterkeys():
                    e = "\nMt.Gox rejected credentials"
                    print self.colorText(e, "shell_self")
                else:
                    self.user   = json["data"]["Login"]
                    self.device = device
                    self.opts.currency = device.standard
                    print "\n{0}{1}".format(
                        self.colorText("Using device: ", "shell_self"),
                        self.colorText(self.dName,       "shell_device"))
                    print "{0}{1}".format(
                        self.colorText("Belongs to: ",   "shell_self"),
                        self.colorText(self.user,        "shell_user") )
        locale.setlocale(locale.LC_ALL, "")
        encoding = locale.getpreferredencoding()
        print self.colorText(u"\nWelcome to GoxCLI!","shell_self")
        print self.colorText(u"Type 'help' to get started.","shell_self")
        try:
            while True:
                self.prompt()
        except EOFError:
            pass

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
                # TODO:
                # Ansi escape-codes mess up raw_input, should find a way around it.
                #sign = u" > " if self.dName else u"> "
                #line = raw_input("\n{currency}{dName}{sign}".format(
                #    currency = self.colorText(currency, "shell_currency"),
                #    dName = self.colorText(self.dName or u'', "shell_user"),
                #    sign = self.colorText(sign, "shell_self")
                #    )) # [CRY] devname $
                print ""
            except EOFError, e:
                print self.colorText(u"exit","shell_self")
                self._shell_exit()
            commands = self.__parse_tokens(self.__tokenize_command(line))
            for ca in commands:
                self.perform(*ca)
        except EOFError, e:
            raise e
        except TokenizationError, e:
            print e
        except KeyboardInterrupt:
            print self.colorText(u"Interrupted by user", "shell_self")
        except InputError,e:
            # Some error occures while parsing user-defined arguments.
            self._error(e.msg,e.arg)
        except RightError,e:
            # Application detected that some rights were missing before
            #   being able to send final request.
            self._error(e.msg,u"")
        except CredentialError, e:
            # Some error occured while decrypting credentials or trying
            #   to use those found in config
            self._error(e.message,u"")
        except DaemonError, e:
            # Could not reach Daemon when trying to read credentials.
            self._error("Not logged in",u"")
        except urllib2.HTTPError,e:
            # Error occurred while trying to reach Mt.Gox.
            self._error("HTTP Error:"," ".join((str(e.code),e.msg)))
        except MtGoxError, e:
            # MtGox replied answer but included error-message.
            self._error(u"Mt.Gox:",e.message)
        except Exception, e:
            traceback.print_exc()

    def perform(self, cmd, args):
        u"Passes commands on to appropriate functions."
        try:
            # Look for private function in self (ShellHandler)
            proc = getattr(self, "_shell_{0}".format(cmd))
        except AttributeError, e:
            # Command needs no special in parsing by ShellHandler.
            try:
                # Look for private function in inherited class (ActionHandler).
                args.insert(0,cmd)
                json = self.action(self.opts,args)
            except InvalidOperation, e:
                # Error when trying to convert string to Decimal
                v = e.message.rpartition(" ")[2].lstrip("u\'").rstrip("'")
                raise InputError("Invalid value: %s " % v, kind="value", arg=v)
            else:
                # Command executed, now sending result (parsed json) to 
                #   appropriate read-function within ShellHandler.
                try:
                    proc = getattr(self, "_shell_read_{0}".format(cmd))
                    proc(json)
                except AttributeError, e:
                    pass
                    # Command exists but json won't be parsed.
                    # (These commands does not show up in help from ShellHandler)
        else:
            # Command needs special parsing before inherited action is called.
            try:
                proc(self.opts,args)
            except InvalidOperation, e:
                # Error when trying to convert string to Decimal
                v = e.message.rpartition(" ")[2].lstrip("u\'").rstrip("'")
                raise InputError("Invalid value: %s " % v, kind="value", arg=v)

    def _error(self,*args):
        u"Prints errormessages in neat colors."
        if len(args) == 1:
            message,arg = args[0],""
        elif len(args) == 2:
            message,arg = args
        else:
            e = "_error takes at most 3 argument (%s given)" % len(args)+1
            raise TypeError(e)
        message = self.colorText(message or u'', "error_message")
        arg     = self.colorText(arg     or u'', "error_arg")
        print u"{message} {arg}".format( message = message, arg = arg )

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
            out = "\nYou must choose method for saving your secret in config."+\
                  "\n1. Encryption. More secure but requires but requires" + \
                  " interactive login." + \
                  "2. Double encoding. NOT SECURE, allows use of commands" + \
                  " without logging in."
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
        
    def _interactive_device(self,devices):
        u"Prompt user to choose device in config, nicely colored."
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
            device = item.format(
                num      = str(num).rjust(4),
                dName    = dev.name.ljust(25),
                currency = dev.standard,
                id       = dev.id,
                sep      = sep
                )
            print self.colorText(device,"shell_self")
        num = u""
        print ""
        while not num.isdigit() or not devices.has_key( int(num) ):
            num = raw_input(self.colorText("Device: ","shell_self"))
        print ""
        return devices[int( num )]

    def _interactive_pw(self):
        u"Get password from user, nicely colored."
        pw = u""
        while not pw:
            # Prompt user to provide password to decrypt secret
            pw = getpass.getpass(self.colorText("Password: ","shell_self"))
        print ""
        return pw
        
        
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
        if not json["data"]:
            print self.colorText("Found no device(s) to delete","error_message")
        else:
            print self.colorText(" Deleted ID(s): ", "shell_self")
            for id in json["data"]: print self.colorText("  " + id, "shell_self")

    def _shell_read_devices(self, json):
        u"Print devices in config."
        sep   = self.colorText("|", "separators")
        line  = " " + self.colorText(("-"*78).center(60), "separators")
        dLine = " " + self.colorText(("="*78).center(60), "separators")
        item  = u" {name} {cry} {sep} {id} {sep} {enc} {sep} {listen}\n{line}"
        print self.colorText(
            item.format(
                name   = "Name".ljust(20),
                cry    = "CRY".ljust(3),
                id     = "ID".ljust(33),
                listen = "Daemon",
                enc    = "Encr",
                sep    = sep,
                line   = dLine
                ),
                "shell_self"
            )
        for device in JsonParser.parse(json)["data"]:
            listening  = "True" if device["listening"] == "True" else ""
            encrypted  = "True" if device["encrypted"] == "True" else ""
            print self.colorText(
                item.format(
                    cry    = device["standard"],
                    name   = device["name"].ljust(20)[:20],
                    id     = device["id"],
                    listen = listening.ljust(4),
                    enc    = encrypted.ljust(4),
                    sep    = sep,
                    line   = line
                    ),
                "shell_self"
                )

    def _shell_read_activate(self, json):
        u"Set credentials after activating."
        json = JsonParser.parse(json)
        self.xml.read()
        device = self.xml.getDevice(json["data"]["id"])
        self.set_credentials(device, self._secret)
        
    def _shell_kill(self, opts, args):
        u"Kill background-service providing credentials to other instances" \
        u" (most likely command-line executed)\n" \
        u"kill [id]\n" \
        u"[id] Specify for which device you no longer want to provide" \
        u" credentials."
        if args:
            if hasattr(args, "__iter__"):
                for id in args:
                    # Get device for every ID
                    device = self.xml.getDevice(id)
                    if not device:
                        self._error(
                            InputError(
                                "Invalid id: %s" % id,
                                 kind = "id", arg = id
                                 )
                            )
                        return
                    # Call this function again with every device retrieved
                    self._shell_kill(opts, device)
                return
            else:
                device = args
        elif len(self.xml.devices) == 1:
            device = self.xml.devices[0]
        else:
            device = self._interactive_device(self.xml.devices)
        try:
            json   = self.killService(device)
        except DaemonError, e:
            self._error(e)
        else:
            text   = "Stopped service: %s (%s)" % (device.id, device.name)
            print self.colorText(text, "shell_self")
        
    def _shell_buy(self, opts, args):
        u"Post bid-order at Mt.Gox, buying bitcoins."
        if len(args):
            match = self.re_sign[opts.currency].match(args[0].decode("utf-8"))
            if match:
                if match.group(2):
                    args[0] = match.group(2)
                else:
                    args[0] = match.group(1)
                opts.asbtc = False
            else:
                opts.asbtc = True
        json = JsonParser.parse(self._action_buy(opts,args))
        self._shell_read_buy(json)

    def _shell_read_buy(self, json):
        u"Reads parsed json _shell_buy."
        text = self.colorText("Added bid: ","shell_self")
        oid = self.colorText(json["data"], "order_bid")
        print u"{0}{1}".format(text,oid)

    def _shell_sell(self, opts, args):
        u"Post ask-order at Mt.Gox, selling bitcoins."
        if len(args):
            # Get compiled general expression for current currency
            match = self.re_sign[opts.currency].match(args[0])
            if match:
                # Check for currency-prefix in front of or after Amount
                if match.group(1) != None:
                    args[0] = match.group(1)
                else:
                    args[0] = match.group(2)
                opts.asbtc = False
            else:
                opts.asbtc = True
        json = JsonParser.parse(self._action_sell(opts,args))
        self._shell_read_sell(json)

    def _shell_read_sell(self, json):
        u"Reads parsed json _shell_sell."
        print u"{0}{1}".format(
            self.colorText("Added ask: ","shell_self"),
            self.colorText(json["data"], "order_ask")
            )

    def _shell_cancel_all(self, opts, args):
        u"Cancel all trades in orderlist.\n"\
        u"cancel_all\n"
        json = self._action_orders(opts, args)
        json = JsonParser.parse(json)
        for order in json[u"data"]:
            oid   = order[u"oid"]
            cJson = self._action_cancel(opts, [oid])
            self._shell_read_cancel(cJson)

    def _shell_read_cancel(self, json):
        u"Cancel trade from type and oid."
        json = JsonParser.parse(json)
        print u"{0}{1}".format(
            self.colorText("Cancelled order: ","shell_self"),
            self.colorText(json["data"]["oid"], "shell_self")
            )

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
        addr = u"Address: {0}".format(json["data"]["addr"])
        print self.colorText(addr,"shell_self")

    def _shell_read_depth(self, json):
        u"Parse, read and print json from depth-action."
        json  = JsonParser.parse(json)
        pForm = ".%sf" % self.xml.currencies[self.opts.currency]["decimals"]
        sep   = self.colorText("|", "separators")
        line  = self.colorText(("-"*78).center(80), "separators")
        dLine = self.colorText(("="*78).center(80), "separators")
        if json["data"]["bids"]:
            ex = json["data"]["bids"][0]
        elif json["data"]["asks"]:
            ex = json["data"]["asks"][0]
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
        if all((json["data"]["bids"],json["data"]["asks"],json.has_key("gap"))):
            lower = Decimal(json["data"]["gap"]["lower"])
            lower = format(lower, pForm)
            lower = lower.rjust(11)[:11]
            print self.colorText(
                u"   {type}  {sep} {lower}".format(
                    type  = "Gap",
                    sep   = sep,
                    lower = lower
                    ),
                "shell_self"
                )
        for side in ("asks","gap","bids"):
            color = "depth_{0}".format(side)
            type  = side.capitalize()[:3]
            type  = self.colorText(type, "shell_self")
            if side == "gap":
                if all((json["data"]["bids"],json["data"]["asks"])):
                    # Both asks and bids is shown, printing info about the gap
                    try:
                        upper = format(json["data"]["gap"]["upper"], pForm)
                        lower = format(json["data"]["gap"]["lower"], pForm)
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
                orders = reversed(json["data"][side])
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
        except AttributeError:
            # ShellHandler does not override this action.
            try:
                # Look for description in MtGoxAPI.
                proc  = getattr(self.api, cmd)
            except AttributeError:
                # Action not found in MtGoxAPI, must be a custom function with
                #   all info described in ActionHandler.
                proc  = getattr(self, "_action_{0}".format(cmd))
                doc   = proc.__doc__.splitlines()
                descr = doc.pop(0)
            else:
                # Description of action found in MtGoxAPI.
                descr = proc.__doc__.splitlines().pop(0)
                # Change docstring to one from ActionHandler which contains
                #   command-line example and argument specifications.
                proc = getattr(self, "_action_{0}".format(cmd))
                doc  = proc.__doc__.splitlines()
        else:
            doc   = proc.__doc__.splitlines()
            descr = doc.pop(0)
            if not len(doc):
                # Only description found in local function, reading example and
                #   argument specifications from ActionHandler.
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
        # Take all words that can fit into a 79 character long string.
        pLine,sep,tail = line[:length].rpartition(" ")
        # Remove words from variable or set to false if no words remains.
        line = line[len(pLine+sep):] if len(line) > length else False
        if (line == False and pLine != tail):
            pLine = "".join((pLine,sep,tail)) 
        yield "".join((" " * rJust, arg)), pLine
        while line:
            # Take more words and print with added spacing.
            pLine,sep,tail = line[:length].rpartition(" ")
            # Remove words from variable or set to false if no words remains.
            line = line[len(pLine+sep):] if len(line) > length else False
            if (line == False and pLine != tail):
                pLine   = "".join( (pLine, sep, tail) )
            yield " "*spacing,pLine

    def _shell_history(self, opts, args):
        u"Request history of your wallet in current currency.\n"\
        u"history [BTC] [all=bool]\n"\
        u"[BTC] Apply BTC as a single argument to request the history of your" \
        u" BTC-wallet."
        u"[all=bool] Show all actions returned, i.e. both BTC and your" \
        u" currently selected currency."
        fh  = False
        opt = OptObject(opts = opts)
        #opt.currency = opts.currency
        for arg in args:
            # Split key-word arguments
            try:
                key,value = arg.split("=")
            except ValueError:
                if arg.upper() == u"BTC":
                    opt.currency = arg.upper()
                else:
                    raise InputError(u"Invalid argument: %s" % arg, arg=arg)
            else:
                if key.lower() == "all":
                    if value.lower() == "true":
                        fh = True
        trades = list()
        page   = 1
        while page:
            json = JsonParser.parse(self._action_history(opt, [str(page)]))
            trades.extend(json["data"]["result"])
            if page < int(json["data"]["max_page"]) and fh:
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
        user  = json["data"]["Login"]
        sep   = self.colorText("|", "separators")
        line  = self.colorText(("-"*78).center(80), "separators")
        dLine = self.colorText(("="*78).center(80), "separators")
        if "get_info" in json["data"]["Rights"]:
            vol = json["data"]["Monthly_Volume"]["value"]
            vol = u"30d Volume : {0}".format(vol)
            fee = u"Fee : {0}%".format(json["data"]["Trade_Fee"])
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
            wallets = json[u"data"][u"Wallets"]
            for currency,data in wallets.iteritems():
                ops     = str(data[u"Operations"])
                balance = data[u"Balance"][u"value"]
                day     = data["Daily_Withdraw_Limit"][u"value"]
                month   = data[u"Monthly_Withdraw_Limit"]
                month   = month[u"value"] if month else u"None"
                s = u" {cur} {sep} {bal} {sep} {ops} {sep} {day} {sep} {month}"
                print self.colorText(
                        s.format(
                            cur     = currency.rjust(7),
                            bal     = balance.rjust(15)[:15],
                            ops     = ops.rjust(7)[-7:],
                            day     = day.rjust(17)[:17],
                            month   = month.rjust(19)[:19],
                            sep     = sep
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
            if r in json[u"data"][u"Rights"]:
                rs += "".join(("  ", s," [X]"))
            else:
                rs += "".join(("  ", s," [ ]"))
        print self.colorText(rs,"shell_self")

    def _shell_read_lag(self, json):
        u"Reads parsed json from _shell_lag."
        json  = JsonParser.parse(json)
        text  = u"Current latency in seconds:"
        value = json["data"]["lag_secs"]
        print self.colorText("{0} {1}".format(text,value), "shell_self")

    def _shell_login(self, opts, args):
        u"Load and decrypt/decode secret from config.\n"\
        u"login [daemon=bool]\n"\
        u"[daemon=bool] Provide credentials to other instances (most likely" \
        u" command-line executed)"
        if len(args) == 1:
            k,v = args[0].split("=")
            if k == "daemon":
                try:
                    daemon = {"true":True, "false":False}[v.lower()]
                except KeyError:
                    raise InputError("Invalid value: %s" % value,
                                     kind = "value", arg = value)
                else:
                    if daemon:
                        try:
                            json = self.runService()
                        except DaemonError, e:
                            self._error(e.message)
                        else:
                            id   = self.device.id
                            text = "Providing the credentials of %s" % id
                            print self.colorText(text, "shell_self")
                        return
            else:
                raise InputError("Invalid argument: %s" % k, arg = k)
        elif len(args):
            raise InputError("Expected 0 or 1 argument, got %s" % len(args))
        else:
            self.set_credentials(*self.login())
        print "\n{0} {1}\n{2} {3}".format(
            self.colorText("Using device: ", "shell_self"),
            self.colorText(self.device.name, "shell_device"),
            self.colorText("Belongs to: "  , "shell_self"),
            self.colorText(self.user       , "shell_user")
            )

    def _shell_logout(self, opts, args):
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
                self.killService(self.device)
                print self.colorText("Killed background-service", "shell_self")
            else:
                raise CredentialError("No credentials saved in client.")

    def _shell_read_orders(self, json, all = False):
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
        orders = json[u"data"]
        for order in orders:
            if all or order[u"currency"] == currency:
                # Get values
                cry      = "   "
                amount   = Decimal( order[u"amount"]["value"] )
                price    = Decimal( order[u"price"]["value"]  )
                kind     = order[u"type"]
                kColor   = "order_%s" % kind.lower() 
                status   = order[u"status"]
                date     = datetime.fromtimestamp( int(order[u"date"]) )
                date     = date.strftime("%Y-%m-%d %H:%M:%S")
                # Format values
                amount = format( amount, ".8f" ).rjust(15)[:15]
                price  = format( price , pForm ).rjust(15)[:15]
                kind   = self.colorText(kind,         "order_%s" % kind)
                amount = self.colorText(amount,       "order_amount")
                oid    = self.colorText(order[u"oid"],"order_oid")
                price  = self.colorText(price,        "order_price")
                date   = self.colorText(date,         "order_time")
                status = self.colorText(" (" + status + ")",    "shell_self")
                # Print values
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
        json  = self.api.info()
        json  = JsonParser.parse(json)
        fee   = Decimal(json["data"][u"Trade_Fee"])/100
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
        trades = json["data"]["trades"]
        if trades:
            sep   = self.colorText("|", "separators")
            line  = self.colorText(("-"*61).center(63),"separators")
            dLine = self.colorText(("="*61).center(63),"separators")
            oid   = json["data"]["order_id"]
            total = json["data"]["total_amount"]["display_short"]
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
        ticker = json["data"]
        pForm  = ".%sf" % self.xml.currencies[self.opts.currency]["decimals"]
        high   = Decimal( ticker[u"high"]["value"] )
        high   = format(high, pForm).rjust(10)
        buy    = Decimal( ticker[u"buy"]["value"] )
        buy    = format(buy, pForm).rjust(10)
        sell   = Decimal( ticker[u"sell"]["value"] )
        sell   = format(sell, pForm).rjust(10)
        last   = Decimal( ticker[u"last"]["value"] )
        last   = format(last, pForm).rjust(10)
        low    = Decimal( ticker[u"low"]["value"] )
        low    = format(low, pForm).rjust(10)
        avg    = Decimal( ticker[u"avg"]["value"] )
        avg    = format(avg, pForm).rjust(10)
        vol    = Decimal( ticker[u"vol"]["value"] )
        vol    = format(vol, '.5f').rjust(10)[0:10]
        print u"{0}{1}".format(self.colorText(u"High: ","shell_self" ),
                               self.colorText(  high,   "ticker_high") )
        print u"{0}{1}".format(self.colorText(u" Buy: ","shell_self" ),
                               self.colorText(   buy,   "ticker_buy" ) )
        print u"{0}{1}".format(self.colorText(u"Last: ","shell_self" ),
                               self.colorText(  last,   "ticker_last") )
        print u"{0}{1}".format(self.colorText(u"Sell: ","shell_self" ),
                               self.colorText(  sell,   "ticker_sell") )
        print u"{0}{1}".format(self.colorText(u" Low: ","shell_self" ),
                               self.colorText(   low,   "ticker_low" ) )
        print u"\n{0}{1}".format(self.colorText(u"Avg.: ","shell_self" ),
                               self.colorText(  avg,    "ticker_avg" ) )
        print u"{0}{1}".format(self.colorText(u"Vol.: ","shell_self" ),
                               self.colorText(  vol,     "ticker_vol" ) )

    def _shell_trades(self, opts, args):
        u"Requests a list of successfull trades from Mt.Gox, returns a" \
        u" maximum of one hundred orders.\n" \
        u"trades [time=int] [since=int]\n" \
        u"[time=int] Returns all trades that happend since <int> number of " \
                u" seconds ago.\n"\
        u"[since=int] Returns trades made after trade with TradeID <int>.\n"
        # TODO u"[steps=int] Cumulate trades and calculate weighted price, return as a list of <int> trades."
        n = None
        if len(args):
            for arg in args:
                try:
                    k,v = arg.split("=")
                except ValueError:
                    raise InputError("Invalid argument: " + arg, arg=arg)
                else:
                    if k == "time":
                        try:
                            td = self._time_diff()
                        except urllib2.HTTPError, e:
                            if e.code == 403:
                                raise RightError(
                                    "Need trade rights to use argument time",
                                    right = "trade",
                                    kind  = "argument",
                                    arg   = "time"
                                    )
                        try:
                            s = int(time.time()*1E6) - td - int(int(v)*1E6)
                        except ValueError:
                            raise InputError(
                                "Invalid value: %s" % v,
                                kind = "value",
                                arg  = v
                                )
                        args = [u"since={0}".format(s)]
        json = self._action_trades(opts,args)
        self._shell_read_trades(json)
    
    def _time_diff(self):
        u"Get difference in local- and server-time"
        if not self.__time_diff:
            oid  = self.api.add_order("bid",10000000,10000,"USD")
            oid  = JsonParser.parse(oid)["data"]
            diff = self.api.orders()
            diff = JsonParser.parse(diff)["data"][-1][u"priority"]
            self.api.cancel("bid",oid)
            self.__time_diff = int(time.time()*1E6) - int(diff)
        return self.__time_diff

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
            sep=sep
            )
        print self.colorText(header, "shell_self")
        print line
        trades = json["data"]
        try:
            pPrice = Decimal(trades[0][u"price"])
        except IndexError:
            empty = "Mt.Gox returned empty table".center(63)
            print self.colorText(empty, "shell_self")
        for trade in trades:
            price = Decimal(trade[u"price"])
            if price < pPrice:
                color = "trades_down"
            elif price > pPrice:
                color = "trades_up"
            else:
                color = "trades_con"
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


class CmdHandler(ActionHandler):
    def setup(self):
        u"Set up settings before running such as optionsparser"
        usage = "Usage: %prog [options] action [arguments]"
        self._parser = OptionParser(add_help_option = False, usage = usage)
        self._parser.add_option(
            "-l", "--list-actions",
            action  = "store_true",
            dest    = "actions",
            default = False,
            help    = "list avaiable actions")
        self._parser.add_option(
            "-h", "--help",
            action  = "store_true",
            dest    = "help",
            default = False,
            help    = "show this help message and exit")
        self._parser.add_option(
            "-b", "--in-btc",
            action  = "store_true",
            dest    = "asbtc",
            default = True,
            help    = "Specify amount in BTC (Standard)")
        self._parser.add_option(
            "-n", "--not-in-btc",
            action  = "store_false",
            dest    = "asbtc",
            default = True,
            help    = "Specify amount in currency.")
        self._parser.add_option(
            "-p", "--pretty-print",
            action  = "store_true",
            dest    = "pretty",
            default = False,
            help    = "Pretty-print result")
        self._parser.add_option(
            "-r", "--raw",
            action  = "store_true",
            dest    = "raw",
            default = False,
            help    = "Mt.Gox-like reults, this is what you want if you're" + \
                      " writing a front-end."
            )
        self._parser.add_option(
            "-s", "--service",
            action  = "store_true",
            dest    = "daemon",
            default = False,
            help    = "Login, decrypt config and start background-service."
            )
        self._parser.add_option(
            "-k", "--kill-daemon",
            action  = "store_true",
            dest    = "kill",
            default = False,
            help    = "Kill running daemon."
            )
        self._parser.add_option(
            "-c", "--currency",
            action  = "store",
            type    = "string",
            dest    = "currency",
            default = None,
            help    = "Specify currency"
            )
        self._parser.add_option(
            "-d", "--device",
            action  = "store",
            type    = "string",
            dest    = "id",
            default = None,
            help    = "Specify device with ID"
            )
        self._parser.add_option(
            "-x", "--xml",
            action  = "store",
            type    = "string",
            dest    = "xml",
            default = "goxcli.xml",
            help    = "Specify config-file"
            )

    def run(self,sysargs):
        u"Launch command from CLI"
        self.opts,args = self._parser.parse_args(sysargs)
        self.xml.read(self.opts.xml)
        if self.opts.help or self.opts.actions:
            self._proc_help(self.opts.help,args)
        else:
            try:
                if self.opts.daemon:
                    result = self.runService()
                elif self.opts.kill:
                    if self.opts.id:
                        device = self.xml.getDevice(self.opts.id)
                        if not self.xml.getDevice(self.opts.id):
                            raise InputError("Invalid id")
                    else:
                        devices = self.xml.devices
                        if len (devices) == 1:
                            device, = devices
                        else:
                            device = self._interactive_device(devices)
                    result = self.killService(device)
                else:
                    if self.opts.id:
                        device = self.xml.getDevice(self.opts.id)
                        if not self.xml.getDevice(self.opts.id):
                            raise InputError("Invalid id")
                    result = self.action(self.opts,args)
            except InputError,e:
                result = JsonParser.build({
                    u"result": u"error",
                    u"error": e.message
                    })
            except MtGoxError, e:
                result = JsonParser.build({
                    u"error": e.message,
                    u"result": u"error"
                    })
            except DaemonError, e:
                result = JsonParser.build({
                    u"error": e.message,
                    u"result": u"error"
                    })
            except CredentialError, e:
                result = JsonParser.build({
                    u"error": e.message,
                    u"result": u"error"
                    })
            except urllib2.HTTPError, e:
                result = JsonParser.build({
                    u"result": u"error",
                    u"error": u"HTTPError %s" % e.code
                    })
            if self.opts.raw:
                sys.stdout.write(result)
            elif self.opts.pretty:
                result = JsonParser.parse(result, force = True)
                print json.dumps(result, sort_keys = False, indent = 4)
            else:
                print result

    def _cli_help(self, opts, args):
        u"Show this help.\n"\
        u"help [command]\n"\
        u"[command] Only show help for a specific command."
        if not args:
            exp  = re.compile(r"^_action_(.+)$")
            cmds = self._get_cmds(exp)
        else:
            cmds = args
        for cmd in cmds:
            self.__print_cmd_info(cmd)

    def _proc_help(self, opt, args = []):
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
                    #   with all info described in ActionHandler.
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
                self._parser.print_help()
                print "\nNOTE: If you want to send a request from" + \
                      " commandline while using a\n    encrypted secret you" + \
                      " may need to have a daemon or shell running\n"
        else:
            # Option -l/--list
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
                (u"block",u"[hash=\"\"] [number...",u"Get trade(s)",False),
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
                (u"withdraw",u"<amount> <address...",u"Withdraw funds",True)
                ): print "{:<12}".format(action) + "{:<22}".format(args) + \
                         "{:<31}".format(descr) + {True:"[*]",False:"[ ]"}[auth]

    def _interactive_activate(self,dName=None):
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

    def prompt(self,prompt,default):
        y = ("y","yes","") if default else ("y","yes")
        a = None
        while a not in ("n","no","y","yes",""):
            a = raw_input("%s [Y/n]: " % prompt).lower()
        if a in y:
            return True
        else:
            return False

    def _interactive_device(self,devices):
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
            dNum = raw_input("Device: ").decode('string_escape')
        return devices[int(dNum)]
        
    def _interactive_pw(self):
        pw = u""
        while not pw:
            # Prompt user to provide password to decrypt secret
            pw = getpass.getpass("Password: ").decode('string_escape')
        return pw

def main():
    if len(sys.argv) == 1:
        locale.setlocale(locale.LC_ALL, "")
        shell = ShellHandler()
        shell.setup(locale.getpreferredencoding())
        shell.run()
    else:
        cmd = CmdHandler()
        cmd.setup()
        cmd.run(sys.argv[1:])


if __name__ == "__main__":
    main()
