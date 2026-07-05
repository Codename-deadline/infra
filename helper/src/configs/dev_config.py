from pydantic.fields import Field

from src.configs.base_config import BaseConfig
from src.configs.common import (
    AppSettings,
    BotConfig,
)
from src.constants import DEV_CONFIG_PATH


class DevConfig(BaseConfig):
    bots: list[BotConfig] = Field(default_factory=list)
    app: AppSettings

    @staticmethod
    def load():
        DevConfig.model_config["yaml_file"] = DEV_CONFIG_PATH
        return DevConfig()  # pyright: ignore[reportCallIssue]
