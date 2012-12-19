#!/usr/bin/env python
# Static

# Various
import os, re, socket

# Encrypt
from Crypto.Cipher import AES
from Crypto import Random
from hashlib import sha256, sha512, md5

# Encode
import binascii
import base64

# Json-Support, cjson is fast and good enough.
# json only needed for prettyprint, will be replaced by regexps.
import json, cjson

# Import parsers
from parsers import *


class CredentialError(Exception):
    pass


class DaemonError(Exception):
    pass


class InputError(Exception):
    def __init__(self, message, arg=None, kind=None):
        if arg:
            self.msg = "Invalid %s:" % (kind if kind else "argument")
        else:
            self.msg = message
        self.arg = arg
        Exception.__init__(self, message)


class JsonError(Exception):
    pass


class JsonParser:
    @staticmethod
    def parse(obj, force = False):
        u"Parse json-strings."
        # cjson is fast and good enough for our purposes
        json = cjson.decode(obj)
        if json.has_key("error") and not force:
            raise ParseError(json[u"error"])
        else:
            return json
    @staticmethod
    def build(obj):
        u"Build json-strings from object(s)."
        return cjson.encode(obj)
    @staticmethod
    def process(action, obj, kwargs, xml, pargs = {}, raw = True):
        try:
            if action == "depth":
                currency = kwargs["currency"]
                decimals = xml.currency(currency)[0]
                parser   = DepthParser(decimals, pargs)
            elif action == "activate":
                parser = ActivationParser(self._xml, kwargs)
            parsed = JsonParser.parse(obj)
            result = parser.process(parsed)
        except InputError, e:
            m = r'{"result": "error", "error": "%s"}'
            return m % e.message
        except ParseError:
            pass
        return JsonParser.build(result) if raw else result


class MtGoxError(Exception):
    pass


class ParseError(Exception):
    pass


class RightError(Exception):
    def __init__(self, message, right=None, kind=None, arg=None):
        self.msg = "Need %s rights to use %s %s" % (right, kind, arg)
        Exception.__init__(self, message)


class TokenizationError(Exception):
    pass


class Crypter:
    @staticmethod
    def encrypt(data, pw, encode = True):
        length = len(data)
        # Hash password to get one 32 bytes long to use as real password.
        key  = sha256(pw).digest()
        # AES use 16-byte blocks, adjust length with zfill to a multiple of 16
        size = -(length*-1/16)*16
        iv   = Random.new().read(AES.block_size)
        aes  = AES.new(key, AES.MODE_CBC, iv)
        data = data.zfill( size )
        out  = iv + aes.encrypt( data )
        # Destroy objects
        return length, binascii.b2a_base64( out ) if encode else out

    @staticmethod
    def decrypt(data, pw, length, decode = True):
        key  = sha256(pw).digest()
        raw = binascii.a2b_base64(data) if decode else data
        iv  = raw[:16]
        enc = raw[16:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        out = aes.decrypt(enc)
        # Remove leading zeros added when encrypted and return result
        return re.sub(r"\b0{" + str(len(out) - length) + "}", "", out)


class DaemonIPC:
    u"Send data to daemon"
    @staticmethod
    def send(data, host = None, inet = False, timeout = 30):
        u"Connect to service"
        if socket.AF_UNIX and not inet:
            SO_PASSCRED = 16
            # Unix inter-communication socket, supposedly more secure
            host = "/tmp/%s-gcli" % os.getuid()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            sock.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
        else:
            # Create a TCP socket (Fallback)
            path = "/tmp/%s-%s-port" % (os.getuid(), "gcli")
            with open(path, "r") as f: port = f.read()
            if not port.isdigit():
                raise DaemonError("Could not connect to service")
            host = ("127.0.0.1", int( port ) )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(host)
        except socket.error, e:
            raise DaemonError("Could not connect to service.")
        snd = sock.getsockopt( socket.SOL_SOCKET, socket.SO_SNDBUF ) / 2
        rcv = sock.getsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF ) / 2
        size = min(snd,rcv)
        sock.send(data)
        reply, data = str(), True
        try:
            while data:
                data = sock.recv(size)
                reply += data
        except socket.timeout:
            raise DaemonError("Socket timed out while connecting to service.")
        else:
            return reply

    @staticmethod
    def setup(host=None):
        if socket.AF_UNIX:
            return 1,DaemonIPC.bindUNIX(host)
        else:
            return DaemonIPC.bindINET(host)

    @staticmethod
    def bindUNIX(host=None):
        # Unix inter-communication socket, supposedly more secure than INET
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        if not host:
            host = "/tmp/%s-gcli" % os.getuid()
        try:
            os.remove(host)
        except OSError:
            if os.path.exists(host):
                try:
                    os.unlink(host)
                except OSError:
                    raise DaemonError(
                        u"Service could not open socket for this device at" + \
                        u" the assigned local address (%s)" % host )
        try:
            sock.bind(host)
        except socket.error:
            # TODO: Catch different kinds of errorcodes (like access denied)
            raise DaemonError(u"Could not open listening socket.")
        else:
            return sock

    @staticmethod
    def bindINET(host=None):
        if host:
            listening,host = host,("127.0.0.1", host)
        else:
            # Pick random port above 1024
            listening = random.randrange(1025,65555)
            host = ("127.0.0.1", listening)
        # TCP socket, fallback or windows-machines...
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(host)
        except socket.error,e:
            # Bind failed using TCP, try again with other ports
            # (TODO: Catch device busy errors instead)
            fail = 1
            while fail < 100:
                listening = random.randrange(1025,65565)
                host = ("127.0.0.1", listening)
                try:
                    sock.bind(host)
                except:
                    fail += 1
                else:
                    break
            else:
                raise DaemonError(u"Could not open listening socket.")
        path = "/tmp/%s-gcli-port" % os.getuid()
        try:
            os.remove(path)
        except OSError:
            if os.path.exists(path):
                raise DaemonError(
                    u"Service could not remove old file to save " + \
                    u" current port. (%s)" % path )
        with open(path, "rw") as f:
            f.write(str(listening))
        return listening, sock

def ErrorParser(e):
    return e.message.rpartition(" ")[2].lstrip("u\'").rstrip("'")