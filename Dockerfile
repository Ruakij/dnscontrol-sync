# syntax=docker/dockerfile:1

FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

ADD https://github.com/StackExchange/dnscontrol/releases/latest/download/dnscontrol-Linux /usr/local/bin/dnscontrol
RUN chmod +x /usr/local/bin/dnscontrol

COPY . .

CMD [ "python3", "daemon.py" ]