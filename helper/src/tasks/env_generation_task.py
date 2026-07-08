import base64
import os
import re
import secrets
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console
from src.configs.dev_config import DevConfig
from src.configs.prod_config import ProdConfig
from src.configs.setup_config import Config
from src.constants import DOTENV_TEMPLATE_PATH
from src.utils import is_production_env, resolve_dotenv_path

from .task import Task


class SecretType(StrEnum):
    BASE64 = "BASE64"
    HEX = "HEX"


@dataclass
class SecretConfig:
    _key: str
    type: SecretType
    length: int

    @property
    def key(self):
        return f"__GEN_{self._key}__"


class EnvGenerationTask(Task):
    name: str = "env generation"
    config_placeholder_pattern = re.compile(r"__CONFIG\.([A-Z_]+)\.([A-Za-z_.]+)__")
    allowed_config_paths: set[str] = {
        "APP.file_storage_size",
        "APP.public_host",
        "APP.public_url",
        "APP.port",
        "SETUP.project_name",
        "SETUP.garage.admin_port",
        "SETUP.garage.app_key_name",
        "SETUP.garage.bucket",
        "SETUP.garage.layout.dev",
        "SETUP.garage.layout.prod",
    }
    secrets_to_generate: list[SecretConfig] = [
        SecretConfig("DB_PWD", SecretType.HEX, 32),
        SecretConfig("KAFKA_CLUSTER_ID", SecretType.BASE64, 16),
        SecretConfig("GARAGE_RPC_SECRET", SecretType.HEX, 32),
        SecretConfig("GARAGE_ADMIN_TOKEN", SecretType.HEX, 32),
        SecretConfig("GARAGE_METRICS_TOKEN", SecretType.HEX, 32),
        SecretConfig("JWT_SECRET", SecretType.BASE64, 64),
        SecretConfig("OTP_HASH_SECRET", SecretType.BASE64, 64),
    ]

    def __init__(
        self,
        console: Console,
        env: str,
        setup_config: Config,
        app_config: DevConfig | ProdConfig,
    ) -> None:
        super().__init__(console)
        self.env = env
        self.setup_config = setup_config
        self.app_config = app_config

    @staticmethod
    def _generate_secret(cfg: SecretConfig):
        assert cfg.length > 0, "Secret length must be > 0"

        value: str = ""
        if cfg.type == SecretType.BASE64:
            value = base64.b64encode(os.urandom(cfg.length)).decode().rstrip("=")
        elif cfg.type == SecretType.HEX:
            value = secrets.token_hex(cfg.length)
        else:
            raise KeyError(f"Unable to generate secret for type {type}")

        return value

    @staticmethod
    def _resolve_path(source: Any, path: str) -> Any:
        value = source
        for part in path.split("."):
            value = getattr(value, part)
        return value

    def _resolve_config_placeholder(self, match: re.Match[str]) -> str:
        namespace: str = match.group(1)
        if not is_production_env(self.env) and namespace.startswith("PROD_"):
            return "<PROD_ONLY_VALUE>"
        namespace = namespace.split("_")[-1]

        path: str = match.group(2)
        allowed_path: str = f"{namespace}.{path}"

        if allowed_path not in self.allowed_config_paths:
            raise ValueError(f"Config placeholder is not allowed: {match.group(0)}")

        try:
            if namespace == "APP":
                if path == "public_host":
                    value = urlparse(str(self.app_config.app.public_url)).hostname
                    if value is None:
                        raise ValueError(
                            f"Unable to resolve config placeholder: {match.group(0)}"
                        )
                else:
                    value = self._resolve_path(self.app_config.app, path)
            elif namespace == "SETUP":
                value = self._resolve_path(self.setup_config, path)
            else:
                raise ValueError(f"Unknown config namespace: {namespace}")
        except AttributeError as e:
            raise ValueError(
                f"Unable to resolve config placeholder: {match.group(0)}"
            ) from e

        return str(value)

    def execute(self) -> None:
        dotenv: Path = resolve_dotenv_path(self.env)

        if dotenv.exists():
            self.console.print(
                f"[yellow]{dotenv.name} already exists, skipping[/yellow]"
            )
            return

        if not DOTENV_TEMPLATE_PATH.exists():
            self.console.print(f"[red]Template not found: {DOTENV_TEMPLATE_PATH}[/red]")
            raise SystemExit(1)

        content: str = DOTENV_TEMPLATE_PATH.read_text()
        for cfg in self.secrets_to_generate:
            content = content.replace(cfg.key, self._generate_secret(cfg))
        content = self.config_placeholder_pattern.sub(
            self._resolve_config_placeholder, content
        )

        unresolved_config = self.config_placeholder_pattern.search(content)
        if unresolved_config is not None:
            raise ValueError(
                f"Unable to resolve config placeholder: {unresolved_config.group(0)}"
            )

        dotenv.write_text(content)
        self.console.print(
            f"[green]Generated {dotenv.name} from {DOTENV_TEMPLATE_PATH.name}[/green]"
        )
