import os
import time
from pathlib import Path

import typer
from rich.console import Console

from src.configs.setup_config import Config
from src.utils import resolve_dotenv_path

from .task import Task

RETRIES_CNT: int = 5
RETRIES_INTERVAL: int = 3


class GarageTask(Task):
    name = "garage setup"

    def __init__(
        self, console: Console, config: Config, layout_capacity_bytes: int, env: str
    ) -> None:
        super().__init__(console)
        self.config = config
        self.layout_capacity_bytes = layout_capacity_bytes
        self.env = env

    @property
    def layout_zone(self) -> str:
        if self.env == "prod":
            return self.config.garage.layout.prod
        return self.config.garage.layout.dev

    def execute(self) -> None:
        import garage_admin_sdk

        bucket_name: str = self.config.garage.bucket
        app_key_name: str = self.config.garage.app_key_name

        with garage_admin_sdk.ApiClient(self._garage_sdk_configuration()) as api_client:
            cluster_api = garage_admin_sdk.ClusterApi(api_client)
            layout_api = garage_admin_sdk.ClusterLayoutApi(api_client)
            bucket_api = garage_admin_sdk.BucketApi(api_client)
            access_key_api = garage_admin_sdk.AccessKeyApi(api_client)
            permission_api = garage_admin_sdk.PermissionApi(api_client)

            for i in range(RETRIES_CNT):
                try:
                    cluster_api.get_cluster_health()
                    break
                except Exception:
                    self.console.print(
                        f"[red][ERROR]: Failed to connect to Garage {i + 1}/{RETRIES_CNT}. Retrying in {RETRIES_INTERVAL} seconds...[/red]"
                    )
                    if i == RETRIES_CNT - 1:
                        raise
                    time.sleep(RETRIES_INTERVAL)

            self._ensure_garage_layout(garage_admin_sdk, cluster_api, layout_api)

            try:
                bucket = bucket_api.get_bucket_info(global_alias=bucket_name)
                self.console.print(
                    f"[yellow]Garage bucket '{bucket_name}' already exists.[/yellow]"
                )
            except garage_admin_sdk.ApiException as e:
                if getattr(e, "status", None) != 404:
                    raise
                bucket = bucket_api.create_bucket(
                    garage_admin_sdk.CreateBucketRequest(globalAlias=bucket_name)
                )
                self.console.print(
                    f"[green]Created Garage bucket '{bucket_name}'.[/green]"
                )

            existing_key = next(
                (key for key in access_key_api.list_keys() if key.name == app_key_name),
                None,
            )

            if existing_key is None:
                app_key = access_key_api.create_key(
                    garage_admin_sdk.UpdateKeyRequestBody(
                        name=app_key_name, neverExpires=True
                    )
                )
                self.console.print(
                    f"[green]Created Garage app key '{app_key_name}'.[/green]"
                )
            else:
                app_key = access_key_api.get_key_info(
                    id=existing_key.id, show_secret_key=True
                )
                self.console.print(
                    f"[yellow]Garage app key '{app_key_name}' already exists.[/yellow]"
                )

            if not app_key.access_key_id or not app_key.secret_access_key:
                self.console.print(
                    "[red][ERROR]: Garage did not return app key credentials.[/red]"
                )
                raise typer.Exit(code=1)

            permission_api.allow_bucket_key(
                garage_admin_sdk.BucketKeyPermChangeRequest(
                    accessKeyId=app_key.access_key_id,
                    bucketId=bucket.id,
                    permissions=garage_admin_sdk.ApiBucketKeyPerm(
                        read=True, write=True
                    ),
                )
            )
            self.console.print(
                f"[green]Granted read/write access for '{app_key_name}' on '{bucket_name}'.[/green]"
            )

            self._update_dotenv(
                resolve_dotenv_path(self.env),
                {
                    "S3_BUCKET": bucket_name,
                    "S3_ACCESS_KEY": app_key.access_key_id,
                    "S3_SECRET_KEY": app_key.secret_access_key,
                },
            )
            self.console.print(
                "[green]Updated application S3 credentials in .env.[/green]"
            )

    def _garage_sdk_configuration(self):
        import garage_admin_sdk

        token: str | None = os.getenv("GARAGE_ADMIN_TOKEN")
        if not token:
            self.console.print("[red][ERROR]: GARAGE_ADMIN_TOKEN is not set.[/red]")
            raise typer.Exit(code=1)

        return garage_admin_sdk.Configuration(
            host=f"http://{self.config.containers.object_storage}:{self.config.garage.admin_port}",
            access_token=token,
        )

    def _ensure_garage_layout(self, garage_admin_sdk, cluster_api, layout_api) -> None:
        status = cluster_api.get_cluster_status()

        if any(node.role is not None for node in status.nodes):
            self.console.print("[yellow]Garage cluster layout already exists.[/yellow]")
            return

        node = next((node for node in status.nodes if node.is_up), None)
        if node is None:
            self.console.print(
                "[red][ERROR]: Garage has no connected node to assign.[/red]"
            )
            raise typer.Exit(code=1)

        role = garage_admin_sdk.NodeRoleChangeRequestOneOf1(
            id=node.id,
            zone=self.layout_zone,
            capacity=self.layout_capacity_bytes,
            tags=[],
        )
        layout_api.update_cluster_layout_without_preload_content(
            garage_admin_sdk.UpdateClusterLayoutRequest(
                roles=[garage_admin_sdk.NodeRoleChangeRequest(role)]
            )
        )
        layout_api.apply_cluster_layout(
            garage_admin_sdk.ApplyClusterLayoutRequest(
                version=status.layout_version + 1
            )
        )
        self.console.print(
            f"[green]Initialized Garage cluster layout with node '{node.id[:16]}...' in zone '{self.layout_zone}'.[/green]"
        )

    def _update_dotenv(self, env_path: Path, updates: dict[str, str]) -> None:
        if not env_path.exists():
            env_path.write_text("")

        lines: list[str] = env_path.read_text().splitlines()
        updated_keys: set[str] = set()
        new_lines: list[str] = []

        for line in lines:
            stripped = line.strip()
            if "=" in stripped and not stripped.startswith("#"):
                key = stripped.split("=", 1)[0].strip()
                if key in updates:
                    new_lines.append(f"{key}={updates[key]}")
                    updated_keys.add(key)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        for key, value in updates.items():
            if key not in updated_keys:
                new_lines.append(f"{key}={value}")

        env_path.write_text("\n".join(new_lines) + "\n")
