from typing import Literal

import typer
from dotenv import load_dotenv
from rich.console import Console
from src.configs.dev_config import DevConfig
from src.configs.prod_config import ProdConfig
from src.configs.setup_config import Config
from src.constants import DEV_CONFIG_PATH, PROD_CONFIG_PATH, SETUP_CONFIG_PATH
from src.tasks.env_generation_task import EnvGenerationTask
from src.tasks.garage_task import GarageTask
from src.tasks.kafka_task import KafkaTask
from src.tasks.pki.tasks.pki_init_task import PkiInitTask
from src.tasks.pki.tasks.pki_validation_task import PkiValidationTask
from src.tasks.postgresql_task import PostgreSQLTask
from src.tasks.task import Task
from src.utils import resolve_dotenv_path

type AppConfig = ProdConfig | DevConfig
app: typer.Typer = typer.Typer()
console: Console = Console()

setup_config: Config | None = None
app_config: AppConfig | None = None

environment: Literal["dev", "prod"] = "dev"


def run_task(task: Task) -> float:
    return task.run()


def load_app_config(env: str) -> AppConfig:
    config_path = PROD_CONFIG_PATH if env == "prod" else DEV_CONFIG_PATH
    if not config_path.exists():
        raise typer.BadParameter(
            f"{env} config is missing: expected {config_path}.\n"
            f"Provide config-{env}.yaml or choose the matching --env."
        )
    return ProdConfig.load() if env == "prod" else DevConfig.load()


def get_configs() -> tuple[Config, AppConfig]:
    if setup_config is None:
        raise typer.BadParameter("Setup Config is not loaded")
    if app_config is None:
        raise typer.BadParameter("App Config is not loaded")
    return setup_config, app_config


@app.callback()
def main(
    env: str = typer.Option("dev", help="Environment config to load (dev/prod)"),
):
    global setup_config, app_config, environment

    if env not in ("prod", "dev"):
        raise typer.BadParameter("Environment must be prod or dev")
    environment = env

    load_dotenv(dotenv_path=resolve_dotenv_path(env))
    try:
        if not SETUP_CONFIG_PATH.exists():
            raise typer.BadParameter(
                f"Setup config is missing: expected {SETUP_CONFIG_PATH}"
            )
        setup_config = Config.load()
        app_config = load_app_config(env)
    except Exception as e:
        console.print(f"[red]Error loading config[/red]:\n{e}")
        raise typer.Exit(code=1)


@app.command(help="Generates .env from .env-template")
def generate_env():
    setup_cfg, app_cfg = get_configs()
    run_task(
        EnvGenerationTask(
            console, env=environment, setup_config=setup_cfg, app_config=app_cfg
        )
    )


@app.command(help="Generates or validates configured PKI material")
def pki_init() -> None:
    setup_cfg, _ = get_configs()
    run_task(PkiInitTask(console, setup_cfg.pki))


@app.command(help="Validates existing PKI material without modifying it")
def pki_validate() -> None:
    setup_cfg, _ = get_configs()
    run_task(PkiValidationTask(console, setup_cfg.pki))


@app.command(help="Sets up S3 by creating an app key, and required buckets")
def garage_setup():
    setup_cfg, app_cfg = get_configs()
    run_task(GarageTask(console, setup_cfg, app_cfg.app.file_storage_size, environment))


@app.command(help="Creates Kafka topics")
def kafka_setup():
    setup_cfg, _ = get_configs()
    run_task(KafkaTask(console, setup_cfg, environment))


@app.command(help="Inserts values into bots table")
def postgresql_setup():
    setup_cfg, app_cfg = get_configs()
    run_task(PostgreSQLTask(console, setup_cfg, app_cfg))


@app.command(help="Runs setup targets (pre application launch)")
def pre_init():
    setup_cfg, app_cfg = get_configs()
    total_elapsed: float = 0.0
    total_elapsed += run_task(
        GarageTask(console, setup_cfg, app_cfg.app.file_storage_size, environment)
    )
    total_elapsed += run_task(KafkaTask(console, setup_cfg, environment))
    console.print(f"Pre-init tasks finished in {total_elapsed:.2f} seconds")


@app.command(help="Runs setup targets (post application launch)")
def post_init():
    setup_cfg, app_cfg = get_configs()
    total_elapsed: float = 0.0
    total_elapsed += run_task(PostgreSQLTask(console, setup_cfg, app_cfg))
    console.print(f"Post-init tasks finished in {total_elapsed:.2f} seconds")


if __name__ == "__main__":
    app()
