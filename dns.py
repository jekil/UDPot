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
from datetime import datetime, timezone

try:
    from twisted.internet.protocol import Factory, Protocol
    from twisted.internet import reactor
    from twisted.names import dns
    from twisted.names import client, server
except ImportError as e:
    print("Twisted requirement is missing, please install it with `pip install twisted`. Error: %s" % e)
    sys.exit()

try:
    from sqlalchemy import create_engine
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Column, Integer, String, DateTime
    from sqlalchemy.orm import sessionmaker
    Base = declarative_base()
except ImportError as e:
    print("SQLAlchemy requirement is missing, please install it with `pip install sqlalchemy`. Error: %s" % e)
    sys.exit()


class Dns(Base):
    """Log table for DNS entries."""
    __tablename__ = "dns"
    id = Column(Integer, primary_key=True)
    src = Column(String)
    src_port = Column(Integer)
    dns_name = Column(String)
    dns_type = Column(String)
    dns_cls = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class HoneyDNSServerFactory(server.DNSServerFactory):
    """DNS honeypot.
    @see: http://notmysock.org/blog/hacks/a-twisted-dns-story.html
    @see: http://blog.inneoin.org/2009/11/i-used-twisted-to-create-dns-server.html
    """

    # Stores who is sending request.
    request_log = {}
    # CLI options.
    opts = None

    def cleanup_old_entries(self):
        """Remove expired entries from request_log to prevent memory leak."""
        now = datetime.now()
        expired_ips = [
            ip for ip, data in self.request_log.items()
            if (now - data["last_seen"]).total_seconds() > self.opts.req_timeout
        ]
        for ip in expired_ips:
            del self.request_log[ip]

    def messageReceived(self, message, proto, address=None):
        # Validate that we have queries to process.
        if not message.queries:
            return

        # Periodically cleanup old entries (every 100 requests).
        if len(self.request_log) % 100 == 0:
            self.cleanup_old_entries()

        # Log info.
        entry = {}
        entry["src_ip"] = address[0]
        entry["src_port"] = address[1]
        entry["dns_name"] = message.queries[0].name.name
        entry["dns_type"] = dns.QUERY_TYPES.get(message.queries[0].type, dns.EXT_QUERIES.get(message.queries[0].type, "UNKNOWN (%d)" % message.queries[0].type))
        entry["dns_cls"] = dns.QUERY_CLASSES.get(message.queries[0].cls, "UNKNOWN (%d)" % message.queries[0].cls)
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
            self.request_log[entry["src_ip"]] = {"count": 1, "last_seen": datetime.now()}
            return server.DNSServerFactory.messageReceived(self, message, proto, address)

    def log(self, data):
        if opts.verbose:
            print(data)
        try:
            record = Dns(src=data["src_ip"], src_port=data["src_port"], dns_name=data["dns_name"], dns_type=data["dns_type"], dns_cls=data["dns_cls"])
            session.add(record)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Database error: {e}")


parser = argparse.ArgumentParser()
parser.add_argument("server", type=str, help="DNS server IP address")
parser.add_argument("-p", "--dns-port", type=int, default=5053, help="DNS honeypot port")
parser.add_argument("-c", "--req-count", type=int, default=3, help="how many request to resolve")
parser.add_argument("-t", "--req-timeout", type=int, default=86400, help="timeout to re-start resolving requests")
parser.add_argument("-s", "--sql", type=str, default="sqlite:///db.sqlite3", help="database connection string")
parser.add_argument("-v", "--verbose", action="store_true", help="print each request")
parser.add_argument("--verbosity", type=int, default=0, choices=[0, 1, 2, 3], help="verbosity level (0-3)")
opts = parser.parse_args()

# DB setup.
engine = create_engine(opts.sql, echo=False)
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

# Create db.
Base.metadata.create_all(engine)

# Create DNS honeypot.
resolver = client.Resolver(servers=[(opts.server, 53)])
factory = HoneyDNSServerFactory(clients=[resolver], verbose=opts.verbosity)
factory.opts = opts
protocol = dns.DNSDatagramProtocol(factory)
factory.noisy = protocol.noisy = opts.verbosity

# Bind and run on UDP and TCP.
reactor.listenUDP(opts.dns_port, protocol)
reactor.listenTCP(opts.dns_port, factory)
reactor.run()
