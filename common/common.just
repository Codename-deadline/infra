project := "deadlines"

dotenv-dev := "../generated/.env"
dotenv-prod := "../generated/.env-prod"
base-project-dir := "../.."

# Generates .env from .env-template if missing
[arg("env", long="env", short="e")]
[group('setup')]
generate-env env="dev": rebuild-helper
    @just _run-task -e {{ env }} -t generate-env

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
    docker compose run --rm helper --env {{ env }} {{ task }}
