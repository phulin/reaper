from __future__ import annotations

from sqlalchemy import Engine, create_engine as sqlalchemy_create_engine
from sqlalchemy.orm import Session, sessionmaker

from reaper.db.config import DatabaseSettings


def create_engine(settings: DatabaseSettings | None = None) -> Engine:
    settings = settings or DatabaseSettings.from_env()
    return sqlalchemy_create_engine(settings.url, future=True)


def create_session_factory(
    settings: DatabaseSettings | None = None,
) -> sessionmaker[Session]:
    return sessionmaker(bind=create_engine(settings), autoflush=False, expire_on_commit=False)
