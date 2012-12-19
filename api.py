#!/usr/bin/env python
# API
from static import *

# Various
import time
import hmac

# HTTP
from contextlib import closing
from ssl import SSLError
import urllib
import urllib2


class MtGoxAPI(object):
    def __init__(self, xml, credentials = None):
        u"Handles requests made to Mt.Gox."
        # Credentials could be a tuple with (key, secret), or as in thise case,
        #  a function that generates (key, secret, counter).
        self.credentials = credentials
        self._xml = xml
        self._url = "https://mtgox.com/api/"

    @property
    def credentials(self):
        if hasattr(self, "_secret"):
            # Credentials has allready been read
            self._counter += 1
        elif hasattr(self._credentials, "__call__"):
            # Credentials is a functions or generator
            return self._credentials()
        else:
            try:
                self._key, self._secret, self._counter = self._credentials
            except (TypeError, ValueError):
                raise CredentialError("Not logged in.")
        return self._key, self._secret, self._counter
    
    @credentials.setter
    def credentials(self, arg):
        if arg:
            if hasattr(arg, "__call__"):
                self._credentials = arg
            elif hasattr(arg, "__len__") and len(arg) == 3:
                self._credentials = arg
            else:
                m = "credentials expected function or container with 3 items"
                raise ValueError(m % len(arg))
        else:
            self._credentials = None

    @credentials.deleter
    def credentials(self):
        self._credentials = None
        try:
            del self._key, self._secret, self._counter
        except AttributeError:
            if hasattr(self, "_key"):
                del self._key
            elif hasattr(self, "_counter"):
                del self._counter

    def _currency(self, currency):
        try:
            return self._currencies[currency]
        except KeyError:
            result = self.currency(None, None)(currency=currency)
            self._currencies[currency] = JsonParser.parse(result)
        return self._currencies[currency]

    def _http_url(self, wpath, api, currency):
        if api and currency:
            url = "".join((self._url, "1/", "".join(("BTC",currency,"/")), wpath))
        elif api:
            url = "".join((self._url, "1/generic/", wpath))
        else:
            url = "".join((self._url, "0/", wpath))
        return url

    def _http_sign(self, auth, params, url):
        if auth:
            # Function requires authentication
            key, secret, counter = self.credentials
            # Timestamp*1000+counter to make multiple requests possible
            params["nonce"] = (int(time.time())*1000)+counter
            # Format the post_data, if not null
            data = urllib.urlencode(params) if len(params) > 0 else None
            try:
                # Decode secret
                secret = base64.b64decode(secret)
                # Hmac-sha512-hash secret and postdata
                hash = hmac.new(secret, data, sha512)
                # Digest hash as binary and encode with base64
                sign = base64.b64encode(str(hash.digest()))
            except TypeError:
                # Catch exception thrown due to bad key or secret
                raise CredentialError(
                    u"Could not sign request due to bad secret or wrong" + \
                    u" password."
                    )
            else:
                # Apply the base64-encoded data together with api-key to header
                headers = {
                        "User-Agent": "GoxCLI",
                        "Rest-Key"  : key,
                        "Rest-Sign" : sign
                        }
            request = urllib2.Request(url, data, headers)
        else:
            data    = urllib.urlencode(params) if len(params) > 0 else None
            request = urllib2.Request(url, data)
        return request, data

    def _http_request(self, request, data, timeout = 15):
        with closing( urllib2.urlopen(request, data, timeout) ) as r:
            return r.read()

    def _request(self, wpath, api = 1, params = {}, currency = None, auth = True):
        url = self._http_url(wpath, api, currency)
        request, data = self._http_sign(auth, params, url)
        try:
            return self._http_request(request, data)
        except SSLError, e:
            error = "Could not reach Mt.Gox. Operation timed out."
        except urllib2.URLError, e:
            if e.code == 403:
                error = "Authorization to this API denied"
            else:
                error = "Could not reach Mt.Gox."
        except urllib2.HTTPError, e:
            if e.code == 403:
                error = "Authorization to this API denied"
            else:
                error = "Could not reach Mt.Gox."
        return r'{"result": "error", "error":"%s"}' % error

    def activate(self, key=None, name=None, pw=None):
        u"Activate application and add device to config. You will need at" \
        u" least some rights to use most of the functions in this application."
        wpath = "activate.php"
        appkey = "52915cb8-4d97-4115-a43a-393c407143ae"
        params = {
                u"name": name,
                u"key":  key,
                u"app":  appkey
                }
        result = self._request(wpath, api=0, params=params, auth=False)
        return result
        
    def add_order(self, kind=None, amount=None, price=None, currency=None):
        wpath = "order/add"
        params = {
                "amount_int":str(amount),
                "price_int":str(price),
                "type":kind
                }
        return self._request(wpath, params=params, currency=currency, auth=True)

    def buy(self, amount=None, price=None, currency=None):
        return self.add_order("bid", amount, price, currency)

    def sell(self, amount=None, price=None, currency=None):
        return self.add_order("ask", amount, price, currency)

    def block(self, hash=None, depth=None):
        u"Retrieve information about a block in bitcoin's blockchain," \
        u" at least one of the arguments hash and number must be defined."
        wpath = "bitcoin/block_list_tx"
        if hash:
            params = dict(hash=hash)
        elif depth:
            params = dict(depth=depth)
        else:
            params = dict()
        return self._request(wpath, params=params, auth=False)

    def btcaddress(self, hash=None):
        u"Requests information about a specific BTC-address."
        wpath = "bitcoin/addr_details"
        params = {"hash":hash}
        return self._request(wpath, params=params, auth=False)

    def cancel(self, kind=None, oid=None):
        u"Cancel order identified with type and oid"
        wpath = "cancelOrder.php"
        params = {
                "type":{"ask":1,"bid":2}[kind],
                "oid":oid
                }
        return self._request(wpath, api=0, params=params, auth=True)
        
    def deposit(self):
        u"Requests address for depositing BTC to your wallet at Mt.Gox."
        wpath = "bitcoin/address"
        return self._request(wpath, auth=True)
        
    def depth(self, currency="USD", full=False):
        u"Request current depth-table at Mt.Gox (aka order book)."
        if full:
            wpath = "fulldepth"
        else:
            wpath = "depth"
        return self._request(wpath, currency = currency, auth = False)

    def history(self, currency="BTC", page=1):
        u"Request wallet history. The history of your BTC-wallet will be" \
        " requested if no currency is defined."
        wpath = "wallet/history"
        params   = {"currency":currency,"page":page}
        return self._request(wpath, params = params, auth = True)

    def info(self):
        u"Retrieve private info from Mt.Gox"
        wpath = "info"
        return self._request(wpath, auth = True)

    def lag(self):
        u"Returns the time MtGox takes to process each order." \
        u" If this value is too high, trades will be delayed and depth-table" \
        u" will probably not be reliable."
        wpath = "order/lag"
        return self._request(wpath, auth = False)
        
    def orders(self):
        u"Requests your open, invalid or pending orders."
        wpath = "orders"
        return self._request(wpath, auth = True)
    
    def status(self, kind=None, oid=None):
        u"Returns trades that have matched the order specified, result will" \
        u" be empty if order still is intact."
        wpath = "order/result"
        params = dict(type = kind, order = oid)
        return self._request(wpath, params=params, auth=True)

    def ticker(self, currency="USD"):
        u"Request latest ticker from Mt.Gox."
        wpath = "ticker"
        return self._request(wpath, currency=currency, auth=False)

    def trades(self, currency="USD", since=None):
        u"Requests a list of successfull trades from Mt.Gox, returns a" \
        u" maximum of one hundred orders."
        wpath = "trades"
        p = {"since":since} if since else {}
        return self._request(wpath, currency=currency, params=p, auth=False)

    def transaction(self, hash=None):
        u"Request information about a transaction within the BTC blockchain."
        wpath = "bitcoin/tx_details"
        params = {"hash":hash}
        return self._request(wpath, params=params, auth=False)

    def withdraw(self,
            currency    = None,
            destination = None,
            amount      = None,
            account     = None,
            green       = False
            ):
        u"Withdraw BTC or Dollars."
        wpath = "withdraw.php"
        g = {False:"0",True:"1"}[green]
        destination = destination.lower()
        if destination == "coupon":
            if currency in ("BTC","USD"):
                params = {
                    u"group1": "".join((currency,"2CODE")),
                    u"amount": amount
                }
            else:
                params = {
                    u"group1": u"USD2CODE",
                    u"amount": amount,
                    u"Currency": currency
                    }
        elif (currency == "BTC") and (destination == "btc"):
            params = {
                u"group1": u"BTC",
                u"btca": account,
                u"amount": amount,
                u"green": g
            }
        elif (currency == "USD") and (destination == "dwolla"):
            params = {
                u"group1": u"DWUSD",
                u"dwaccount": account,
                u"amount": amount,
                u"green": g
            }
        elif (currency == "USD") and (destination == "lr"):
            params = {
                u"group1": u"USD",
                u"account": account,
                u"amount": amount,
                u"green": g
            }
        elif (currency == "USD") and (destination == "paxum"):
            params = {
                u"group1": u"PAXUMUSD",
                u"paxumaccount": account,
                u"amount": amount,
                u"green": g
            }
        else:
            raise InputError("Impossible combination of arguments and/or currency.")
        return self._request(wpath, api = 0, params=params, auth=True)

    def request( self, action, **kwargs):
        try:
            result = getattr(self, action)(**kwargs)
        except (CredentialError, InputError), e:
            return r'{"result": "error", "error":"%s"}' % e.message
        except TypeError, e:
            error = "Invalid parameter: %s" % ErrorParser(e)
            return r'{"result": "error", "error":"%s"}' % error
        return result