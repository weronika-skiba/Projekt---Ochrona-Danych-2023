FROM python:3.11-alpine
WORKDIR /home
COPY hello.py /home
COPY requirements.txt /home/requirements.txt
ENV FLASK_APP=hello.py
ENV FLASK_RUN_HOST=0.0.0.0
RUN apk add --no-cache gcc musl-dev linux-headers
RUN pip install --upgrade pip
RUN pip install -r /home/requirements.txt
EXPOSE 5000
CMD ["flask", "run"]