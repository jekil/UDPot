FROM python:3.12-slim
LABEL maintainer="Alessandro Tanasi (@jekil)"

ENV DNS_SERVER=8.8.8.8

WORKDIR /app

COPY requirements.txt .
RUN pip --no-cache-dir install -r requirements.txt

COPY dns.py .

RUN mkdir -p /data

EXPOSE 5053/udp
EXPOSE 5053/tcp
VOLUME /data

CMD ["sh", "-c", "python dns.py -p 5053 -v -s sqlite:////data/db.sqlite3 -j /data/dns_logs.jsonl $DNS_SERVER"]
