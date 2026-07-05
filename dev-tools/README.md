# Local development

## Clone this repository:

```bash
git clone git@github.com:Codename-deadline/infra.git
```

## Clone the rest of the project

```bash
just clone
```

`-j` flag is available. It directly corresponds to `git`'s `-j`

## Project setup

### Creating dev config

Copy the [config-dev-template.yaml](../configs/templates/config-dev-template.yaml) into [configs](../configs)
and rename it to `config-dev.yaml`. Fill in the missing info about bots. You can leave it empty if you do not wish to run bots.

### First run

#### Generating secrets

```bash
just generate-env
```

Now you can add bot tokens in [.env](../generated/.env) if you want to run them.
For that edit the `TELEGRAM_BOT_TOKEN` variable

#### Initial setup

```bash
just first-run
```

This will:

- Pull required infra docker images e.g `kafka`, `redis`...
- Download project dependencies
- Setup virtual environments
- Create kafka topics
- Insert bots data from config into DB
- Initialize S3 storage (creating buckets and an app key)
- And more...

### You are ready to go!

From now on to start the application use

```bash
just run
```

This will skip

1. Dependency install
2. All initializing steps for DB, S3, kafka...

Nothing bad will happen if you call `first-run` again.
Helper image is designed to be idempotent, but it will take longer than otherwise necessary to launch an already set up app.
