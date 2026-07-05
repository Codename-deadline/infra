import asyncio
import os
import sys

from rich.console import Console

from src.configs.dev_config import DevConfig
from src.configs.prod_config import ProdConfig
from src.configs.setup_config import Config

from .task import Task

RETRIES_CNT: int = 5
RETRIES_INTERVAL: int = 3


class PostgreSQLTask(Task):
    name = "postgresql setup"

    def __init__(
        self, console: Console, setup_config: Config, app_config: DevConfig | ProdConfig
    ) -> None:
        super().__init__(console)
        self.setup_config = setup_config
        self.app_config = app_config

    def execute(self) -> None:
        asyncio.run(self._register_bots())

    async def _register_bots(self) -> None:
        import asyncpg

        connection = None

        for i in range(RETRIES_CNT):
            try:
                connection = await asyncpg.connect(
                    host=self.setup_config.containers.db,
                    port=5432,
                    database=os.getenv("DB_DB"),
                    user=os.getenv("DB_USER"),
                    password=os.getenv("DB_PWD"),
                )
                break
            except Exception:
                self.console.print(
                    f"[red][ERROR]: Failed to connect to db {i + 1}/{RETRIES_CNT}. Retrying in {RETRIES_INTERVAL} seconds...[/red]"
                )
                if i == RETRIES_CNT - 1:
                    break
                await asyncio.sleep(RETRIES_INTERVAL)

        if connection is None:
            self.console.print("[red]Could not connect to database.[/red]")
            sys.exit(1)

        self.console.print(f"Registering {len(self.app_config.bots)} bots...")

        try:
            for i, bot in enumerate(self.app_config.bots):
                try:
                    await connection.execute(
                        """
                        INSERT INTO bots (id, bot_id, messenger, username)
                        VALUES ($1, $2, $3, $4);
                        """,
                        i,
                        bot.id,
                        bot.messenger,
                        bot.username,
                    )
                    self.console.print(
                        f"[green]Registered @{bot.username}. Messenger: {bot.messenger.name.capitalize()}[/green]"
                    )
                except asyncpg.exceptions.UniqueViolationError:
                    self.console.print(
                        f"[yellow]Bot '{bot.username}' already exists.[/yellow]"
                    )
        except asyncpg.exceptions.UndefinedTableError:
            self.console.print(
                "[red][ERROR]: Table 'bots' does not exist. Start api first to create it[/red]"
            )

        await connection.close()
