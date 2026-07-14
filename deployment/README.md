# Creating a production deployment

## Prerequisites

To proceed further make sure that you have the following software installed:

- `git`
- `docker` and `docker compose`
- `just`

Also note, that this setup will not work with `docker context`, so the following steps should be performed on the target machine.

## Fetching the repo

On the machine where you want to host this app run

```bash
git clone --depth 1 https://github.com/Codename-deadline/infra.git \
&& cd infra/deployment
```

To pull everything required to get you through the setup.

## Creating a config

1. Go to [config templates](../configs/templates) and copy `config-prod-template.yaml` to the [configs](../configs) folder.
2. Rename it to `config-prod.yaml`

### Fill in missing details

#### Application data

- port. If you want multiple ports to be used one can edit the [nginx config](gateway/nginx)
- public_url. E.g: `http://example.com`
- file_storage_size. How much space (in bytes) will be available for `S3` to store your files

#### Telegram bot data:

Bot ID. The part before `:` in the token from `@BotFather`.
If the token returned is `0123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`. Then bot id is `0123456789`

Therefore an example of a filled config for a `@the-best-telegram-bot` with a token `0123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` is the following:

```yaml
bots:
    - id: 0123456789
      username: "the-best-telegram-bot"
      messenger: "TELEGRAM"
```

## Generating secrets

Go back to the folder this `README.md` is in. And run the following command

```bash
just generate-env -e prod
```

This will create a [.env-prod](../generated/.env-prod) file containing app secrets.

### Adding missing details

Open [.env-prod](../generated/.env-prod) and scroll to the bottom until you see `Bot tokens` section.

Replace all `<YOUR_BOT_TOKEN>` with actual bot tokens. For example:

`TELEGRAM_BOT_TOKEN=<YOUR_BOT_TOKEN>` -> `TELEGRAM_BOT_TOKEN=0123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

You can save and close the file now.

## Generating certificates / PKI

```bash
just generate-pki -e prod
```

## First start

Now the only step remaining is to launch an app. For that run the following command and wait:

```bash
just initial-deploy
```

After it finishes executing you should have a deployment up and running!
