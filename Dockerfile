# syntax=docker/dockerfile:1

FROM python:3.10.9

WORKDIR /app

COPY . .

RUN pip3 install -r requirements.txt


EXPOSE 8000

ENTRYPOINT ["python3", "app.py"]