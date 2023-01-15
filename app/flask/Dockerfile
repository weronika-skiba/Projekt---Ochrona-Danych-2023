FROM python:3.7-slim

WORKDIR = /var/www
ADD ./app /app
COPY ./requirements.txt .
RUN pip3 install -r requirements.txt

ENV FLASK_APP hello.py
ENV FLASK_RUN_PORT 8000
ENV FLASK_RUN_HOST 0.0.0.0

EXPOSE 8000

CMD ["flask", "run"]

CMD
