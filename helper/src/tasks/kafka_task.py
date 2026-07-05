import os

from rich.console import Console

from src.configs.setup_config import Config

from .task import Task


class KafkaTask(Task):
    name = "kafka setup"

    def __init__(self, console: Console, config: Config) -> None:
        super().__init__(console)
        self.config = config

    def execute(self) -> None:
        import kafka
        from kafka.admin import NewTopic

        container_name: str = self.config.containers.kafka
        kafka_port: int = int(os.getenv("KAFKA_PORT", 9092))
        kafka_client = kafka.KafkaAdminClient(
            bootstrap_servers=f"{container_name}:{kafka_port}"
        )
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

        kafka_client.close()
