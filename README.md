GoxCLI
=========

## Features in short ##

* Interact with Mt.Gox API
* Option to encrypt secret
* Multiple currencies
* Includes a shell-like interface
* Runs from command-line and return replies as jsons
* Use multiple devices/accounts
* Buy and sell bitcoins
* List and cancel orders
* Withdraw bitcoins
* Display account balance
* Display tickers
* Display depths and do some primitive parsing of orderbook
* Calculate profitable short/long prices from an initial price

And of course, more...


### Requirements ###

* Python 2.6 or a newer 2.* release.
* PyCrypto 2.0.1 or later.
* Python cjson

### Instructions ###

Shell:

To start a GoxShell simply run goxcli.py without any following arguments, usually by running:

$ python goxcli.py

When shell has started, type "help" to get a detailed list of actions avaiable.


CLI:

To read the in application help, run the following command from a *nix shell:

$ python goxcli.py -h

To get a list of actions avaiable, this commands is used:

$ python goxcli.py -l [action]

The action-parameter is optional and gives you detailed information about a specific action.

### Activation ###

You need to activate your client to authenticate with Mt.Gox.

* Log in to your account at MtGox.com
* Navigate into Security Center
* Go to Application Acces and generate a key with at least some rights
* Run GoxCLI-shell
* Type "activate <activationkey>" where <activationkey> is the key you retrieved from Mt.Gox
* Follow instructions on screen

NOTE: If you're activating your application more than once, you will end up with multiple devices in config, the command to delete old devices is named "delete".

### Daemon ###

If you're using encrypted method of saving your key, please note that to run actions that requires authentication with Mt.Gox. you will have to start a service with the -s/--service option from command-line (and then follow instructions on scrren). If you prefer starting the service from within a GoxShell you could run this command:

$ login daemon=True

However, if you've not encrypted your secret, none of this will not be necessary and you can run whatever action you'd like without a service running.

### Other ###

Here is the history I found on goxsh's website that Optonic wrote, which I feel is worth to include:

* goxsh was originally written by ahihi and first announced on June 17, 2011 on the Bitcoin Forum.

* On July 21, 2011 I decided to add some basic ANSI-color support to goxsh and therefor forked goxsh at github: Optonic/goxsh 0.11 was born. With goxsh 0.13 color settings were sourced out into a separate config file. With 0.16c the ability to login with API-key/secret was added to goxsh. The ability to login with 
username and password has been removed in release 0.20 as it had become deprecated but new features were added.

* On July 30, 2011 I announced my fork on the Bitcoin Forum. 

My, Trasp, own notes about GoxCLI:

This started out as a fork of goxsh. I was supposed to update it to Mt.Gox's API v1, enable the use of multiple currencies and implement a new interface which you could reach straight from command-line. After I realized it would become a real mess I rewrote it pretty much from scratch. Since you will still see alot of the goxsh-style and a little of the code in goxcli I suppose you still could call GoxCLI a fork of goxsh.

-------------------------

I, Trasp, would also like to thanks Mt.Gox for contributing to this application. And a special thanks goes to MagicalTux for his neverending support in #mtgox

Also, like all other suckers out there I would also warmly welcome tiny donations, being a broke student and all :). If you think I deserved it, here's my address: 1NMmr9upNA37t91UkVagK2X5m55jvLMTWb
