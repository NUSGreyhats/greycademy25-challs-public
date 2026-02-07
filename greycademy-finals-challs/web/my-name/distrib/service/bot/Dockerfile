FROM pwn.red/admin-bot

COPY config.js .
USER root
COPY run.sh .
RUN chmod +x run.sh
USER node

ENTRYPOINT [ "/app/run.sh" ]