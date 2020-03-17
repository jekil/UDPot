[![Build Status](https://travis-ci.org/jekil/UDPot.svg?branch=master)](https://travis-ci.org/jekil/UDPot)

# dns.py

The idea behind this script is to provide a DNS honeypot which logs all requests to a SQLite database and with a
configurable interactivity level.

It can be configured to resolve only a number of DNS requests to seems like an open resolver to an attacker, after that
it acts as a sinkhole.

For each request coming from a source IP only a custom number of requests are really resolved (sending back a DNS reply)
before working as a sinkhole; after a configurable timeout, it can restart the loop.

## Requirements

The script is developed for Python 3 and the following libraries are required:

 * twisted
 * sqlalchemy

You can install them with (you need python-dev package to compile them):

    pip install -r requirements.txt

## Usage

You can print the option list using the help **-h** option:

    $ python dns.py -h
    usage: dns.py [-h] [-p DNS_PORT] [-c REQ_COUNT] [-t REQ_TIMEOUT] [-s] [-v]
                    server

    positional arguments:
      server                DNS server IP address

    optional arguments:
      -h, --help            show this help message and exit
      -p DNS_PORT, --dns-port DNS_PORT
                            DNS honeypot port
      -c REQ_COUNT, --req-count REQ_COUNT
                            how many request to resolve
      -t REQ_TIMEOUT, --req-timeout REQ_TIMEOUT
                            how many request to resolve
      -s, --sql             database connection string
      -v, --verbose         print each request

You can run the DNS honeypot with the following command, you have to add the IP of the DNS server you use to resolve
the first bunch of queries to seems like an open resolver (in this example we use 8.8.8.8):

    $ python dns.py 8.8.8.8

Now your DNS honeypot is listening on both port 5053 UDP and TCP.
If you want to bind it to port 53 you have to:

 * run it as root and use option **-p** which is really **not recommended**
 * add an iptables rule to redirect traffic from port 53 to port 5053

Example iptables rules to redirect traffic:

    iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 53 -j REDIRECT --to-ports 5053
    iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5053

Some other arguments are optional:

 * **-p** is used to bind DNS honeypot service on a given port
 * **-c** how many requests should be resolved (sending a DNS reply) like a real open resolver
 * **-t** timeout to re-start resolving requests (sending a DNS reply) like a real open resolver
 * **-s** choose a SQL database (default SQLite)
 * **-v** verbose logging (prints each request)
