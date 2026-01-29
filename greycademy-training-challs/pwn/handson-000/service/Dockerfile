from ubuntu:24.04

run apt-get update && apt-get -y install socat python3

workdir /app
copy ./chall.py .

cmd ["socat", "TCP-LISTEN:5000,nodelay,reuseaddr,fork", "EXEC:\"python3 /app/chall.py\""]
