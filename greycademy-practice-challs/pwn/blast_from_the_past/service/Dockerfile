FROM ubuntu:22.04 AS app

FROM pwn.red/jail

COPY --from=app / /srv
COPY ./challenge /srv/app/run
COPY ./flag.txt /srv/app/flag.txt

RUN chmod +x /srv/app/run
RUN chmod 644 /srv/app/flag.txt
