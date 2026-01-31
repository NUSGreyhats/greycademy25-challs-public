FROM ubuntu:24.04 AS app

FROM pwn.red/jail

COPY --from=app / /srv
COPY ./moonlightfactory /srv/app/run
COPY ./flag.txt /srv/app/flag.txt

RUN chmod +x moonlightfactory
RUN chmod 644 flag.txt
