from typing import final, override

from rich.console import Console
from src.configs.pki_config import PkiConfig
from src.tasks.pki.services.pki_service import PkiService
from src.tasks.task import Task


@final
class PkiInitTask(Task):
    name: str = "PKI initialization"

    def __init__(self, console: Console, config: PkiConfig) -> None:
        super().__init__(console)
        self._service: PkiService = PkiService(config)

    @override
    def execute(self) -> None:
        result = self._service.initialize()
        if result == "generated":
            self.console.print(
                f"[green]Generated PKI material in {self._service.output_directory}[/green]"
            )
        else:
            message = (
                "[green]Existing PKI material is valid in"
                f" {self._service.output_directory}[/green]"
            )
            self.console.print(message)
