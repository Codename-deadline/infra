from src.configs.base_config import BaseConfig
from src.configs.common import ContainerSettings, GarageSettings, KafkaSettings
from src.configs.pki_config import PkiConfig
from src.constants import SETUP_CONFIG_PATH


class Config(BaseConfig):
    project_name: str
    containers: ContainerSettings
    kafka: KafkaSettings
    garage: GarageSettings
    pki: PkiConfig

    @staticmethod
    def load():
        Config.model_config["yaml_file"] = SETUP_CONFIG_PATH
        return Config()  # pyright: ignore[reportCallIssue]
