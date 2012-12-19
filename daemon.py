#!/usr/bin/env python
# Daemon
from static import *
from parsers import *
from api import MtGoxAPI

# Various
from collections import deque
from random import choice
from struct import calcsize, unpack
import string, sys, uuid

class Daemon(object):
    def __init__(self, xml):
        u"Background service providing credentials after logging in."
        self.xml        = xml
        self.handshakes = xml.handshakes
        self.ws         = self.xml.websocket
        self.subscriptions = dict()
        #if self.ws:
        #    self.api = DaemonAPI()
        #else:
        self.api = MtGoxAPI(xml)
        self._counter  = 0
        self._children = deque((), 5)
        rs = lambda: choice(string.ascii_uppercase + string.digits)
        self.salt = "".join((rs() for x in range(10)))

    @property
    def counter(self):
        self._counter += 1
        return self._counter

    @counter.setter
    def counter(self, v):
        self._counter = int(v)
    
    def __gen_checksum(self, handshake):
        if self.handshakes:
            return md5(self.salt + handshake).hexdigest()
        else:
            return handshake
    
    def __get_device(self, handshake):
        if handshake and handshake[0] == "h":
            checksum = self.__gen_checksum(handshake)
        else:
            checksum = handshake
        if self.subscriptions.has_key(checksum):
            channel, credentials, length = self.subscriptions[checksum]
            if length:
                plain = Crypter.decrypt(credentials, handshake, length, decode=True)
                key, secret = plain.split("|")
                del handshake, plain
            else:
                key, secret = credentials
                del handshake
        else:
            raise CredentialError("Invalid handshake")
        return channel, key, secret

    def __set_device(self, id = None, pw = None):
        if id:
            device = self.xml.getDevice(id)
            if not device:
                m = r'{"error": "Credentials rejected", "result": "error"}'
                raise CredentialError(m)
            elif device.length and not pw:
                m = r'{"error": "Missing parameter pw", "result": "error"}'
                raise JsonError(m)
            if device.length:
                try:
                    secret = Crypter.decrypt(device.secret, pw, device.length)                       
                except UnicodeDecodeError:
                    m = r'{"error": "Credentials rejected", "result": "error"}'
                    raise CredentialError(m)
            else:
                secret = device.secret
            key = device.key
            #if self.ws:
            #    channel = self.api.subscribePriv(key, secret, self.counter)
            #else:
            channel = None
        else:
            m = r'{"error": "Missing parameter id", "result": "error"}'
            raise JsonError(m)
        if self.handshakes:
            handshake = "h%s" % uuid.uuid4().hex
            length, credentials = Crypter.encrypt( "|".join((key, secret)), handshake )
        else:
            handshake = id
            length, credentials = 0,[key, secret]
        checksum = self.__gen_checksum(handshake)
        info  = (channel, credentials, length)
        json  = {"action":"register","checksum":checksum,"info":info}
        return handshake, JsonParser.build(json)

    def run(self):
        u"Start daemon threads and listen on socket"
        listening, sock = DaemonIPC.setup()
        # Allow only one connection at a time
        sock.listen(1)
        # Fork process and put it in background. The essence is the same as:
        #  if not((os.fork() == 0 and os.fork() == 0)): sys.exit(0)
        if os.fork():
            # Main process
            result = { "result": "success", "return": str( listening ) }
            return JsonParser.build(result)
        else:
            # New process
            if not os.fork():
                # Third and last process, our background service
                # NOTE: Without the last fork the process dies when the user log
                #       out or close the running shell.
                self.listening = listening
                #sys.stdin  = open(os.devnull, 'r')
                #sys.stdout = open(os.devnull, 'w')
                #sys.stderr = open(os.devnull, 'w')
                # Point background-job to _listen()
                self._listen(sock)
            # Exit second process and background-job when done.
            sys.exit(0)

    def _listen(self, sock):
        running = True
        # Listen for incoming connections
        snd = sock.getsockopt( socket.SOL_SOCKET, socket.SO_SNDBUF ) / 2
        rcv = sock.getsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF ) / 2
        self.size = min(snd,rcv)
        while running:
            # Wait for a new connection
            counter = self.counter
            connection, address = sock.accept()
            pid = self._auth( connection, address )
            if pid in self._children:
                # Subprocess calling back
                running = self._handleLoop( connection, address )
            else:
                # Create subprocess to deal with the connection
                fork = os.fork()
                if fork:
                    self._children.append(fork)
                else:
                    self._handle( connection, address, counter )
        sys.exit(0)

    def _auth(self, connection, address):
        if socket.AF_UNIX:
            SO_PEERCRED = 17
            creds = connection.getsockopt(
                socket.SOL_SOCKET,
                SO_PEERCRED,
                calcsize('3i')
                )
            pid, uid, gid = unpack('3i',creds)
            if uid == os.getuid():
                return pid

    def _handleLoop(self, connection, address):
        u"Handles calls from subprocess"
        data   = connection.recv(self.size)
        parsed = JsonParser.parse(data)
        action = parsed["action"].lower()
        running = True
        if action == "register":
            checksum = parsed["checksum"]
            self.subscriptions[checksum] = parsed["info"]
            reply = r'{"result": "success"}'
        elif action == "logout":
            handshake = parsed.pop("handshake", None)
            checksum = self.__gen_checksum(handshake)
            try:
                info = self.subscriptions.pop(checksum)
            except KeyError:
                reply = r'{"return": "Invalid handshake", "result": "error"}'
            else:
                #if self.ws:
                #    channel = info[0]
                #    self.api.unsubscribePriv(channel)
                reply = r'{"result": "success"}'
        elif action == "terminate":
            reply = r'{"return": "Terminated.", "result": "success"}'
            running = False
        self._respond(reply, connection)
        connection.close()
        return running

    def _handle(self, connection, address, counter ):
        try:
            data   = connection.recv(self.size)
            action, parsed = self._read(data)
            action = action.lower()
            if action == "login":
                handshake, fdata = self.__set_device(**parsed)
                reply = DaemonIPC.send(fdata)
                if reply == r'{"result": "success"}':
                    reply = r'{"return": "%s", "result": "success"}' % handshake
                else:
                    reply = r'{"return": "Could not login", "result": "error"}'
            elif action == "logout":
                reply = DaemonIPC.send(data)
            elif action == "terminate":
                reply = DaemonIPC.send(data)
            else:
                reply = self._perform(action, parsed, counter)
        except (JsonError, CredentialError), e:
            self._respond(e.message, connection)
        else:
            self._respond(reply, connection)
        # Close connection and kill subprocess
        connection.send("")
        connection.close()
        sys.exit(0)

    def _respond(self, reply, connection):
        length = len(reply)
        try:
            connection.send(reply)
        except socket.error, e:
            if e.errno == 90:
                size = self.size
                for d in (reply[x:x+size] for x in xrange(0, length, size)):
                    connection.send(d)

    def _read(self, data):
        try:
            parsed = JsonParser.parse(data)
        except cjson.DecodeError:
            m = r'{"result": "error", "error": "Malformed message"}'
            raise JsonError(m)
        else:
            try:
                action = parsed.pop("action")
            except KeyError, e:
                m = r'{"result": "error", "error": "Missing parameter action"}'
                raise JsonError(m)
            else:
                return action, parsed

    def _perform(self, action, parsed, counter):
        handshake = parsed.pop("handshake", None)
        parseArgs = parsed.pop("parse",     None)
        if handshake:
            try:
                channel, key, secret = self.__get_device(handshake)
            except CredentialError:
                pass
            else:
                self.api.credentials = (key, secret, counter)
                del channel, key, secret
        reply = self.api.request(action, **parsed)
        if parseArgs or action == "activate":
            reply = JsonParser.process(action, reply, parsed, self.xml, parseArgs)
        del self.api.credentials
        return reply