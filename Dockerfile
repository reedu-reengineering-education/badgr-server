FROM python:3.7-slim

RUN mkdir /badgr_server
WORKDIR /badgr_server

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y default-libmysqlclient-dev \
                       python3-dev \
                       python3-cairo \
                       build-essential \
                       xmlsec1 \
                       libxmlsec1-dev \
                       pkg-config

COPY requirements.txt                   /badgr_server
COPY manage.py                          /badgr_server
COPY .docker/etc/uwsgi.ini              /badgr_server
COPY .docker/etc/wsgi.py                /badgr_server
COPY apps                               /badgr_server/apps
COPY .docker/etc/settings_local.prod.py /badgr_server/apps/mainsite/settings_local.py

RUN pip install uwsgi
RUN pip install -r requirements.txt
