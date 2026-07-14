import shutil
from pathlib import Path
from typing import Literal, final
from uuid import uuid4

from src.configs.pki_config import PkiConfig
from src.constants import GENERATED_DIR
from src.tasks.pki.services.internal.pki_load import PkiLoadService
from src.tasks.pki.services.internal.pki_validation import PkiValidationService
from src.tasks.pki.services.internal.pki_write import PkiWriteService


@final
class PkiService:
    def __init__(
        self, config: PkiConfig, generated_directory: Path = GENERATED_DIR
    ) -> None:
        self._config: PkiConfig = config
        self._generated_directory: Path = generated_directory.resolve()
        self._output_directory: Path = (
            self._generated_directory / config.output_directory
        ).resolve()
        self._writer = PkiWriteService(config)
        self._validator = PkiValidationService(config, PkiLoadService(config))

    @property
    def output_directory(self) -> Path:
        return self._output_directory

    def initialize(self) -> Literal["generated", "validated"]:
        if self._output_directory.exists():
            self.validate()
            return "validated"

        self._generated_directory.mkdir(parents=True, exist_ok=True)
        staging_directory = self._generated_directory / (
            f".{self._config.output_directory.name}-{uuid4().hex}.tmp"
        )
        try:
            self._writer.write(staging_directory)
            _ = staging_directory.replace(self._output_directory)
        except Exception:
            shutil.rmtree(staging_directory, ignore_errors=True)
            raise
        return "generated"

    def validate(self) -> None:
        self._validator.validate(self._output_directory)
