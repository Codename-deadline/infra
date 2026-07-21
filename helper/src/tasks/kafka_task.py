import os
import ssl
from pathlib import Path
from typing import Literal, override

from rich.console import Console
from src.configs.setup_config import Config
from src.constants import GENERATED_DIR
from src.utils import is_production_env

from .task import Task


class KafkaTask(Task):
    name: str = "kafka setup"

    def __init__(
        self,
        console: Console,
        config: Config,
        environment: Literal["dev", "prod"],
    ) -> None:
        super().__init__(console)
        self.config: Config = config
        self.environment: Literal["dev", "prod"] = environment

    @override
    def execute(self) -> None:
        import kafka
        from kafka.admin import NewTopic

        container_name: str = self.config.containers.kafka
        kafka_port: int = int(os.getenv("KAFKA_PORT", 9092))
        bootstrap_servers = f"{container_name}:{kafka_port}"
        if is_production_env(self.environment):
            kafka_client = kafka.KafkaAdminClient(
                bootstrap_servers=bootstrap_servers,
                security_protocol="SSL",
                ssl_context=self._ssl_context(),
            )
        else:
            kafka_client = kafka.KafkaAdminClient(bootstrap_servers=bootstrap_servers)

        try:
            existing_topics: set[str] = set(kafka_client.list_topics())
            new_topics: list[NewTopic] = [
                NewTopic(
                    name=topic.name,
                    num_partitions=topic.partitions,
                    replication_factor=topic.replicas,
                )
                for topic in self.config.kafka.topics
                if topic.name not in existing_topics
            ]

            if new_topics:
                kafka_client.create_topics(new_topics=new_topics)
                self.console.print(f"[green]Created {len(new_topics)} topics.[/green]")
            else:
                self.console.print("[yellow]All topics already exist.[/yellow]")
        finally:
            kafka_client.close()

    def _ssl_context(self) -> ssl.SSLContext:
        identity_directory: Path = (
            GENERATED_DIR
            / self.config.pki.output_directory
            / "entities"
            / self.config.kafka.admin_identity
        )
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=identity_directory / "ca.pem",
        )
        context.load_cert_chain(
            certfile=identity_directory / "cert.pem",
            keyfile=identity_directory / "key.pem",
        )
        return context
