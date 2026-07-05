FROM python:3.14-alpine

ARG UID=1000
ARG GID=1000
ARG USER=deadlines-setup

RUN addgroup -g $GID $USER && \
    adduser -D -u $UID -G $USER $USER

WORKDIR /setup
RUN apk add --no-cache git

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src src

USER $USER
ENTRYPOINT ["python3", "-m", "src.main"]
