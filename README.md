[![Build Status](https://travis-ci.org/jekil/UDPot.svg?branch=master)](https://travis-ci.org/jekil/UDPot)
[![Twitter Follow](https://img.shields.io/twitter/follow/jekil.svg?style=social)](https://twitter.com/jekil)

# dns.py

The idea behind this script is to provide a DNS honeypot which logs all requests to a SQLite database and/or JSON file with a configurable interactivity level.

It can be configured to resolve only a number of DNS requests to seems like an open resolver to an attacker, after that
it acts as a sinkhole.

For each request coming from a source IP only a custom number of requests (default 3) are really resolved (sending back a DNS reply)
before working as a sinkhole; after a configurable timeout (default 1 day), it can restart the loop.

## Docker

A docker image is available on [DockerHub](https://hub.docker.com/r/jekil/udpot).
Run it with:

    docker run --name udpot -p 5053:5053/udp -p 5053:5053/tcp -d jekil/udpot
    
It will run UDPot on port 5053 UDP and TCP, if you want to use it on another port you can bind it with docker or redirect it with iptables (explained below).

### Variables

- *DNS_SERVER*: host for DNS resolution

### Volumes

- *data*: where SQLite database is stored

## Requirements

The script is developed for Python 3 and the following libraries are required:

 * twisted
 * sqlalchemy

You can install them with (you need python-dev package to compile them):

    pip install -r requirements.txt

## Usage

You can print the option list using the help **-h** option:

    $ python dns.py -h
    usage: dns.py [-h] [-p DNS_PORT] [-c REQ_COUNT] [-t REQ_TIMEOUT] [-s SQL]
                  [-j JSON_LOG] [-v] [--verbosity {0,1,2,3}]
                  server

    positional arguments:
      server                DNS server IP address

    optional arguments:
      -h, --help            show this help message and exit
      -p DNS_PORT, --dns-port DNS_PORT
                            DNS honeypot port (default: 5053)
      -c REQ_COUNT, --req-count REQ_COUNT
                            how many request to resolve (default: 3)
      -t REQ_TIMEOUT, --req-timeout REQ_TIMEOUT
                            timeout to re-start resolving requests (default: 86400)
      -s SQL, --sql SQL     database connection string (default: sqlite:///db.sqlite3)
      -j JSON_LOG, --json-log JSON_LOG
                            JSON log file path (optional, JSONL format)
      -v, --verbose         print each request
      --verbosity {0,1,2,3}
                            verbosity level (default: 0)

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

 * **-p** is used to bind DNS honeypot service on a given port (default: 5053)
 * **-c** how many requests should be resolved (sending a DNS reply) like a real open resolver (default: 3)
 * **-t** timeout to re-start resolving requests (sending a DNS reply) like a real open resolver (default: 86400 seconds = 1 day)
 * **-s** choose a SQL database connection string (default: sqlite:///db.sqlite3)
 * **-j** enable JSON logging to file in JSONL format (one JSON object per line)
 * **-v** verbose logging (prints each request to stdout)
 * **--verbosity** set the Twisted framework verbosity level (0-3)

## Logging Options

UDPot supports multiple logging backends that can be used independently or together:

### SQLite Database (default)

By default, all DNS requests are logged to a SQLite database (`db.sqlite3`). Each entry includes:
- Transport protocol (UDP/TCP)
- Source IP and port
- DNS query name, type, and class
- Timestamp

### JSON Lines Format

Enable JSON logging with the `-j` option to write logs in JSONL format (newline-delimited JSON):

    $ python dns.py 8.8.8.8 -j dns_logs.jsonl

Each line is a valid JSON object:

```json
{"timestamp": "2026-01-06T10:30:45.123456+00:00", "transport": "UDP", "src_ip": "192.168.1.100", "src_port": 54321, "dns_name": "example.com", "dns_type": "A", "dns_cls": "IN"}
```

You can use both SQLite and JSON logging simultaneously:

    $ python dns.py 8.8.8.8 -j dns_logs.jsonl -v

Or disable SQLite and use only JSON:

    $ python dns.py 8.8.8.8 -s "" -j dns_logs.jsonl

### Processing JSON Logs

JSONL files can be easily processed with tools like `jq`:

```bash
# Count requests by source IP
cat dns_logs.jsonl | jq -r .src_ip | sort | uniq -c | sort -rn

# Filter only A record queries
cat dns_logs.jsonl | jq 'select(.dns_type == "A")'

# Get unique queried domains
cat dns_logs.jsonl | jq -r .dns_name | sort -u
```
