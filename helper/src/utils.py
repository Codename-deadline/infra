from pathlib import Path

from src.constants import DOTENV_DEV_PATH, DOTENV_PROD_PATH


def resolve_dotenv_path(env: str) -> Path:
    return DOTENV_PROD_PATH if is_production_env(env) else DOTENV_DEV_PATH


def is_production_env(env: str) -> bool:
    return env == "prod"
