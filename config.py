#!/usr/bin/env python
# Config
from static import *

# Various
import re
import base64
import uuid
import xml.dom.minidom

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
        for pNode in self.cfg.childNodes:
            if pNode.tagName == "devices":
                self.cfg.removeChild(pNode)
                break
        self.cfg.insertBefore(devices, self.cfg.firstChild)
        self.write()

    @devices.deleter
    def devices(self,device):
        # Compare id with all devices in XML
        for dNode in self.cfg.getElementsByTagName(device.id):
            # Remove device on match
            dNode.parentNode.removeChild(dNode)
    
    @property
    def handshakes(self):
        try:
            return self._handshakes
        except NameError:
            if not self.xml:
                raise RuntimeError("XML not parsed")
            else:
                m = "Missing attribute: handshakes"
                raise InputError("Invalid XML: %s" % m, kind = "XML", arg = m)
    
    @property
    def websocket(self):
        try:
            return self._websocket
        except NameError:
            if not self.xml:
                raise RuntimeError("XML not parsed")
            else:
                m = "Missing attribute: websocket"
                raise InputError("Invalid XML: %s" % m, kind = "XML", arg = m)

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
        u"Read config and set dictionaries with new settings."
        if path: self.path = path
        self.doc = self.parse(self.path)
        cfg = self.doc.firstChild
        if cfg.tagName == "GoxCLI":
            self.cfg = cfg
        else:
            raise InputError("Error reading XML")
        for sNode in self.cfg.childNodes:
            if sNode.tagName == "settings":
                break
        lDict = { "currencies": lambda: self._readCurrencies(node, currencies),
                  "shell"     : lambda: self._readColors(node, colors),
                  "daemon"    : lambda: self._readDaemon(node)
                  }
        for node in sNode.childNodes:
            if lDict.has_key(node.tagName): lDict[node.tagName]()

    def _readColors(self, node, read):
        u"Read colors from document and return settings in a dictionary."
        if read:
            for cNode in node.childNodes:
                if cNode.tagName == "colors":
                    readable = cNode
                elif cNode.tagName == "ansi":
                    ansi     = cNode.childNodes
            if not all((readable,ansi)):
                margs = []
                if not readable: margs.append("readable")
                if not ansi:     margs.append("ansi")
                m = "%s: %s" % ("Missing section: ", margs.__str__())
                raise InputError("Invalid XML: %s" % m, kind = "XML", arg = m)
            else:
                # Convert ansi-table in config to dictionary
                ansi  = dict((c.tagName, c.attributes["value"].value) for c in ansi)
                # Create lambda that get the tagName of a device and match it
                #  against the keys in our fresh dictionary of ansi-codes.
                color = lambda n: (n.tagName, ansi[n.attributes["value"].value])
                # Save a dict with keys from element colors and values from ansi
                self.colors = dict(color(n) for n in readable.childNodes)
        return self.colors

    def _readCurrencies(self, node, read):
        u"Read currencies from document and return settings in a dictionary."
        if read:
            cDict  = dict()
            for cNode in node.childNodes:
                currency = cNode.tagName
                try:
                    prefix   = cNode.attributes["symbol"].value
                    decimals = int( cNode.attributes["decimals"].value )
                except KeyError:
                    m = "%s: %s" % ("Malformed currency: ", currency.upper())
                    raise InputError("Invalid XML: %s" % m, kind = "XML", arg = m)
                else:
                    cDict[currency] = dict(
                        decimals = decimals,
                        prefix = prefix
                        )
            self.currencies = cDict
        return self.currencies

    def _readDaemon(self, node):
        u"Read colors from document and return settings in a dictionary."
        if node.hasAttribute("handshakes"):
            handshakes       = node.attributes["handshakes"].value.lower()
            self._handshakes = {"true":True,"false":False}.get(handshakes,False)
        else:
            handshakes = false
        if node.hasAttribute("websocket"):
            websocket       = node.attributes["websocket"].value.lower()
            self._websocket = {"true":True,"false":False}.get(websocket, False)
        else:
            websocket = False
            self._websocket = False
        for sNode in node.childNodes:
            tagName = sNode.tagName
            if tagName in ("depth","trades"):
                value = sNode.attributes.get("value", False)
                if value:
                    value = value.value
                    if tagName == "trades":
                        value = int(value) if value.isdigit() else 0
                    else:
                        value = {"true": True,"false": False}.get(value, False)
                    path  = sNode.attributes.get("path",  None)
                    both  = (value, path)
                    setattr(self, "_" + tagName, both)
            elif tagName == "output":
                output = dict()
                value              = sNode.attributes.get("value","false")
                out                = sNode.attributes.get("outgoing","false")
                output["value"]    = {"true": True,"false": False}.get(value, False)
                output["outgoing"] = {"true": True,"false": False}.get(out,   False)
                nodes = ["depth","trades","tickers","devices"]
                for oNode in sNode.childNodes:
                    if oNode.tagName in nodes:
                        nodes.remove(oNode.tagName)
                        value = oNode.attributes.get("value", False)
                        value = {"true": True,"false": False}.get(value, False)
                        path  = oNode.attributes.get("path",  None)
                        output[sNode.tagName] = (value, path)
                # Inactivate all missing settings in output
                for missing in nodes:
                    output[missing] = (False, "")

    def currency(self, currency):
        u"Read single currency from config."
        currency = currency.upper()
        if self.currencies:
            try:
                return sorted(self.currencies[currency].itervalues())
            except KeyError:
                raise InputError("Invalid currency:  %s" % str(currency),
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
