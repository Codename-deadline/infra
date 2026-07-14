from typing import final, override

from rich.console import Console
from src.configs.pki_config import PkiConfig
from src.tasks.pki.services.pki_service import PkiService
from src.tasks.task import Task


@final
class PkiValidationTask(Task):
    name: str = "PKI validation"

    def __init__(self, console: Console, config: PkiConfig) -> None:
        super().__init__(console)
        self._service: PkiService = PkiService(config)

    @override
    def execute(self) -> None:
        self._service.validate()
        self.console.print(
            f"[green]PKI material is valid in {self._service.output_directory}[/green]"
        )
