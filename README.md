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
