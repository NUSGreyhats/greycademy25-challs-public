FROM alpine:3.18

RUN apk add busybox-extras

WORKDIR /www
COPY ./index.html /www/

EXPOSE 8080
CMD ["httpd", "-f", "-p", "8080", "-h", "/www"]