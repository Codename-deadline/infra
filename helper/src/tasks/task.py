from abc import ABC, abstractmethod
from time import perf_counter

from rich.console import Console

TASK_START_MESSAGE_LENGTH: int = 80


class Task(ABC):
    name: str

    def __init__(self, console: Console) -> None:
        self.console = console

    def print_start(self) -> None:
        header: str = f" Starting task: {self.name} ".center(
            TASK_START_MESSAGE_LENGTH, "="
        )
        self.console.print(f"\n[blue]{header}[/blue]\n")

    def print_end(self, elapsed: float) -> None:
        self.console.print(f"\nFinished task: {self.name} in {elapsed:.2f} seconds")

    def run(self) -> float:
        self.print_start()
        start = perf_counter()
        self.execute()
        elapsed = perf_counter() - start
        self.print_end(elapsed)
        return elapsed

    @abstractmethod
    def execute(self) -> None:
        pass
