FROM python:3.14-slim

RUN mkdir /app

COPY main.py index.html error.html /app

WORKDIR /app

CMD [ "python", "main.py" ]
