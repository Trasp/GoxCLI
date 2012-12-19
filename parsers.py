#!/usr/bin/env python
# Parsers
from static import *
from decimal import Decimal, InvalidOperation
from config import DeviceItem
from random import choice
import string

class ActivationParser(object):
    def __init__(self, xml, args={}):
        self.xml = xml
        try:
            for arg, value in args.iteritems():
                arg = arg.lower()
                if hasattr(self, arg):
                    setattr(self, arg, value)
                else:
                    raise InputError("Invalid argument: %s" % arg, arg = arg)
        except ValueError:
            raise InputError("Invalid argument")
        
    @property
    def name(self):
        try:
            return self._name
        except AttributeError:
            choices = string.ascii_uppercase + string.digits
            name = "GoxCLI_"
            name += "".join(choice(choices) for x in range(10))
            self._name = name
            return name
    @name.setter
    def name(self,value):
        self._name = value

    @property
    def pw(self):
        try:
            return self._pw
        except AttributeError:
            return None
    @pw.setter
    def pw(self,value):
        self._pw = value

    @property
    def key(self):
        return None
    @key.setter
    def key(self,value):
        self._key = value

    def process(self, json):
        json    = JsonParser.parse(json)
        key     = json[u"Rest-Key"].decode('string_escape')
        _secret = json[u"Secret"].decode('string_escape')
        if self.pw:
            length, secret = Crypter.encrypt(_secret, self.pw)
        else:
            length, secret = 0, _secret
        rights = dict()
        for rkey in ("get_info","trade","deposit","withdraw","merchant"):
            rights[rkey] = True if json[u"Rights"].get(rkey,False) else False
        device = DeviceItem(self.name, key, secret, encrypted=length)
        self.xml.addDevice(device)
        json = {
                "return":{"name":self.name,"id":device.id,"rights":rights},
                "result":"success"
                }
        return json

class DepthParser(object):
    def __init__(self, decimals, args = {}):
        u"Parses OrderBook and generate new jsons"
        self.__sides = ("asks","bids")
        self._cPrec = Decimal(1) / 10 ** decimals
        try:
            for arg, value in args.iteritems():
                arg = arg.lower()
                if hasattr(self, arg):
                    try:
                        setattr(self, arg, value)
                    except (InvalidOperation, ValueError):
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

    @iv.setter
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

    def process(self, json):
        u"Parse depth-table from Mt.Gox, returning orders matching arguments"
        # Check if user has applied any arguments so we need to parse and strip the json
        json      = json["return"]
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
                    if side == "bids": orders = reversed(orders)
            table[side] = list(orders)
        json = {
                "return":table,
                "result":"success"
                }
        return json

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
            if maxValue  and totalV > maxValue:  break
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
        if not((price_int, amount_int, stamp, precision, iv)):
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
                raise InputError("Missing argument: precision")
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