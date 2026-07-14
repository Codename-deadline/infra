project := "deadlines"

dotenv-dev := "../generated/.env"
dotenv-prod := "../generated/.env-prod"
pki-dotenv := "../generated/pki/passwords.env"
base-project-dir := "../.."

# Generates .env from .env-template if missing
[arg("env", long="env", short="e")]
[group('setup')]
generate-env env="dev": rebuild-helper
    @just _run-task -e {{ env }} -t generate-env

# Generates or validates configured certificates without starting services
[arg("env", long="env", short="e")]
[group('setup')]
generate-pki env="prod": rebuild-helper
    @just _run-task -e {{ env }} -t pki-init

# Validates generated certificates without modifying them
[arg("env", long="env", short="e")]
[group('setup')]
validate-pki env="prod": rebuild-helper
    @just _run-task -e {{ env }} -t pki-validate

# Rebuild the docker image for application setup / initialization
[group('setup')]
rebuild-helper:
    docker build \
        --build-arg UID=$(id -u) \
        --build-arg GID=$(id -g) \
        -t {{ project }}-setup ../helper

[arg("env", long="env", short="e")]
[arg("task", long="task", short="t")]
_run-task task env="dev": rebuild-helper
    #!/bin/sh
    dotenv="{{ dotenv-dev }}"
    if [ "{{ env }}" = "prod" ]; then
        dotenv="{{ dotenv-prod }}"
    fi

    set --
    if [ -f "$dotenv" ]; then
        set -- "$@" --env-file "$dotenv"
    fi
    if [ -f "{{ pki-dotenv }}" ]; then
        set -- "$@" --env-file "{{ pki-dotenv }}"
    fi

    docker compose "$@" run --rm helper --env {{ env }} {{ task }}
