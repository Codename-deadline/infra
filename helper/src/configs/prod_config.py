from pydantic.fields import Field
from pydantic_core import Url

from src.configs.base_config import BaseConfig
from src.configs.common import (
    AppSettings,
    BotConfig,
)
from src.constants import PROD_CONFIG_PATH


class ProdAppSettings(AppSettings):
    public_url: Url
    port: int


class ProdConfig(BaseConfig):
    bots: list[BotConfig] = Field(default_factory=list)
    app: ProdAppSettings

    @staticmethod
    def load():
        ProdConfig.model_config["yaml_file"] = PROD_CONFIG_PATH
        return ProdConfig()  # pyright: ignore[reportCallIssue]
