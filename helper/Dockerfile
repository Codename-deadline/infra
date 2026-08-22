FROM python:3.14-alpine

ARG UID=1000
ARG GID=1000
ARG USER=deadlines-setup

RUN addgroup -g $GID $USER && \
    adduser -D -u $UID -G $USER $USER

WORKDIR /setup
RUN apk add --no-cache git
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /bin/

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev
COPY src src

USER $USER
ENTRYPOINT ["uv", "run", "--no-sync", "-m", "src.main"]
