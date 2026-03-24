from __future__ import annotations

import sys
from pathlib import Path

from alembic import command
from alembic.config import Config


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "src" / "reaper" / "db" / "migrations"


def build_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("prepend_sys_path", str(ROOT / "src"))
    return config


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    config = build_config()

    if not argv:
        command.upgrade(config, "head")
        return 0

    action, *rest = argv

    if action == "upgrade":
        command.upgrade(config, rest[0] if rest else "head")
        return 0
    if action == "downgrade":
        command.downgrade(config, rest[0] if rest else "-1")
        return 0
    if action == "current":
        command.current(config)
        return 0
    if action == "history":
        command.history(config)
        return 0
    if action == "revision":
        message = " ".join(rest).strip() or "new revision"
        command.revision(config, message=message, autogenerate=True)
        return 0

    raise SystemExit(
        "usage: python scripts/migrate.py [upgrade [REV]|downgrade [REV]|current|history|revision MESSAGE]"
    )


if __name__ == "__main__":
    raise SystemExit(main())
