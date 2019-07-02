FROM python:3
MAINTAINER Alessandro Tanasi (@jekil)

ENV DNS_SERVER 8.8.8.8

ADD dns.py requirements.txt /
RUN mkdir /data
RUN pip --no-cache-dir install -r requirements.txt

ENTRYPOINT python ./dns.py -p 5053 -v -s sqlite:///data/db.sqlite2 $DNS_SERVER
EXPOSE 5053
VOLUME /data
