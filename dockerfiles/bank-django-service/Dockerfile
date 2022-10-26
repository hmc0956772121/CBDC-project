# syntax=docker/dockerfile:1
FROM python:3.6.8

ENV PYTHONDONTWRITEBYTECODE=1

ENV PYTHONUNBUFFERED=1

WORKDIR /code

COPY requirements.txt /code/

RUN apt-get clean && apt-get -y update && \
    apt-get -y install libsasl2-dev python-dev libldap2-dev libssl-dev libsnmp-dev libgmp-dev libmpfr-dev libmpc-dev

RUN pip install -r requirements.txt 