"""Configuration files for AWARE."""

from pathlib import Path

CONFIG_DIR = Path(__file__).parent
DEFAULT_RULES_FILE = CONFIG_DIR / "default_rules.yaml"

__all__ = ["CONFIG_DIR", "DEFAULT_RULES_FILE"]