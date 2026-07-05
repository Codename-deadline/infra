from pathlib import Path

BASE_DIR: Path = Path(__file__).parent.parent
CONFIGS_DIR: Path = BASE_DIR / "configs"
GENERATED_DIR: Path = BASE_DIR / "generated"

DOTENV_TEMPLATE_PATH: Path = BASE_DIR / ".env-template"
DOTENV_DEV_PATH: Path = GENERATED_DIR / ".env"
DOTENV_PROD_PATH: Path = GENERATED_DIR / ".env-prod"

SETUP_CONFIG_PATH: Path = CONFIGS_DIR / "setup-config.yaml"
DEV_CONFIG_PATH: Path = CONFIGS_DIR / "config-dev.yaml"
PROD_CONFIG_PATH: Path = CONFIGS_DIR / "config-prod.yaml"
