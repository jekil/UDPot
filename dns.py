#!/usr/bin/env python
# Copyright (C) 2014 Alessandro Tanasi (@jekil)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import argparse
from datetime import datetime

try:
    from twisted.internet.protocol import Factory, Protocol
    from twisted.internet import reactor
    from twisted.names import dns
    from twisted.names import client, server
except ImportError as e:
    print "Twisted requirement is missing, please install it with `pip install twisted`. Error: %s" % e
    sys.exit()

try:
    from elixir import *
except ImportError as e:
    print "Elixir requirement is missing, please install it with `pip install elixir`. Error: %s" % e
    sys.exit()


class Dns(Entity):
    """Log table for DNS entries."""
    src = Field(Unicode(255))
    src_port = Field(Integer)
    dns_name = Field(Unicode(255))
    dns_type = Field(Unicode(255))
    dns_cls = Field(Unicode(255))
    created_at = Field(DateTime, default=datetime.now)

class HoneyDNSServerFactory(server.DNSServerFactory):
    """DNS honeypot.
    @see: http://notmysock.org/blog/hacks/a-twisted-dns-story.html
    @see: http://blog.inneoin.org/2009/11/i-used-twisted-to-create-dns-server.html
    """

    # Stores who is sending request.
    request_log = {}
    # CLI options.
    opts = None

    def messageReceived(self, message, proto, address=None):
        # Log info.
        entry = {}
        entry["src_ip"] = unicode(address[0])
        entry["src_port"] = unicode(address[1])
        entry["dns_name"] = unicode(message.queries[0].name.name)
        entry["dns_type"] = unicode(dns.QUERY_TYPES.get(message.queries[0].type, dns.EXT_QUERIES.get(message.queries[0].type, "UNKNOWN (%d)" % message.queries[0].type)))
        entry["dns_cls"] = unicode(dns.QUERY_CLASSES.get(message.queries[0].cls, "UNKNOWN (%d)" % message.queries[0].cls))
        self.log(entry)

        # Forward the request to the DNS server only if match set conditions,
        # otherwise act as honeypot.
        if entry["src_ip"] in self.request_log and (datetime.now() - self.request_log[entry["src_ip"]]["last_seen"]).total_seconds() < self.opts.req_timeout:
            if self.request_log[entry["src_ip"]]["count"] < self.opts.req_count:
                self.request_log[entry["src_ip"]]["count"] += 1
                self.request_log[entry["src_ip"]]["last_seen"] = datetime.now()
                return server.DNSServerFactory.messageReceived(self, message, proto, address)
            else:
                self.request_log[entry["src_ip"]]["last_seen"] = datetime.now()
                return
        else:
            self.request_log[entry["src_ip"]] = {"count": 1, "last_seen": 0, "last_seen": datetime.now()}
            return server.DNSServerFactory.messageReceived(self, message, proto, address)

    def log(self, data):
        if opts.verbose:
            print data
        Dns(src=data["src_ip"], src_port=data["src_port"], dns_name=data["dns_name"], dns_type=data["dns_type"], dns_cls=data["dns_cls"])
        session.commit()


parser = argparse.ArgumentParser()
parser.add_argument("server", type=str, help="DNS server IP address")
parser.add_argument("-p", "--dns-port", type=int, default=5053, help="DNS honeypot port")
parser.add_argument("-c", "--req-count", type=int, default=3, help="how many request to resolve")
parser.add_argument("-t", "--req-timeout", type=int, default=86400, help="how many request to resolve")
parser.add_argument("-s", "--sql", action="store_true", default="sqlite:///db.sqlite3", help="database connection string")
parser.add_argument("-v", "--verbose", action="store_true", help="print each request")
opts = parser.parse_args()

# DB setup.
metadata.bind = opts.sql
# SQL statement debug, set to True to print SQL statements.
metadata.bind.echo = False

# Create db.
setup_all()
create_all()

verbosity = 3

# Create DNS honeypot.
resolver = client.Resolver(servers=[(opts.server, 53)])
factory = HoneyDNSServerFactory(clients=[resolver], verbose=verbosity)
factory.opts = opts
protocol = dns.DNSDatagramProtocol(factory)
factory.noisy = protocol.noisy = verbosity

# Bind and run on UDP and TCP.
reactor.listenUDP(opts.dns_port, protocol)
reactor.listenTCP(opts.dns_port, factory)
reactor.run()
