FROM python:3.12-alpine AS python

WORKDIR /app

COPY ./server /app
RUN pip3 install -r /app/requirements.txt

ENTRYPOINT ["python3"]
CMD ["main.py"]
