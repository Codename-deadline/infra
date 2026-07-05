from enum import StrEnum

from pydantic import BaseModel, Field


class ContainerSettings(BaseModel):
    kafka: str
    redis: str
    object_storage: str
    db: str


class KafkaTopic(BaseModel):
    name: str
    partitions: int = Field(default=1)
    replicas: int = Field(default=1)


class KafkaSettings(BaseModel):
    topics: list[KafkaTopic]


# TODO: Duplicate of the bots enum
class Messenger(StrEnum):
    TELEGRAM = "TELEGRAM"


class BotConfig(BaseModel):
    id: int
    username: str
    messenger: Messenger


class AppSettings(BaseModel):
    file_storage_size: int


class GarageLayoutSettings(BaseModel):
    dev: str
    prod: str


class GarageSettings(BaseModel):
    admin_port: int
    layout: GarageLayoutSettings
    bucket: str
    app_key_name: str
