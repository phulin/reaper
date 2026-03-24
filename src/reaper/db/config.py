from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_DATABASE_URL = "postgresql+psycopg://localhost:5432/reaper"


@dataclass(slots=True)
class DatabaseSettings:
    """Database settings sourced from the environment."""

    url: str = DEFAULT_DATABASE_URL

    @classmethod
    def from_env(cls) -> "DatabaseSettings":
        return cls(url=os.getenv("REAPER_DATABASE_URL", DEFAULT_DATABASE_URL))
