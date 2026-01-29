from redpwn/jail
copy --from=ubuntu@sha256:1c4cc37c10c4678fd5369d172a4e079af8a28a6e6f724647ccaa311b4801c3c9 / /srv

env JAIL_TIME=0
add ./chall /srv/app/run
add ./flag.txt /srv/app/flag.txt

run chmod +x /srv/app/run
