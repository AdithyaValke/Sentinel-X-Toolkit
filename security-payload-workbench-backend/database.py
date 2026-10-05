"""SQLAlchemy engine and session setup for the Flask backend."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from dotenv import dotenv_values
from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Base metadata for future application models; the initial schema is empty."""


@dataclass(frozen=True)
class Database:
    engine: Engine
    sessions: sessionmaker[Session]

    def dispose(self) -> None:
        self.engine.dispose()


def normalize_database_url(database_url: str | URL) -> URL:
    """Parse DATABASE_URL and select psycopg 3 for default PostgreSQL URLs."""
    if isinstance(database_url, str):
        value = database_url.strip()
        if not value:
            raise ValueError("DATABASE_URL is empty")
        if value.lower().startswith("postgres://"):
            value = "postgresql://" + value[len("postgres://"):]
    else:
        value = database_url

    try:
        url = make_url(value)
    except (ArgumentError, TypeError, ValueError) as error:
        raise ValueError("DATABASE_URL is invalid") from error

    if url.drivername == "postgresql":
        url = url.set(drivername="postgresql+psycopg")
    return url


def database_url_from_environment(
    environment: Mapping[str, str] | None = None,
    *,
    required: bool = True,
    dotenv_path: str | Path | None = None,
) -> URL | None:
    values = os.environ if environment is None else environment
    database_url = values.get("DATABASE_URL")
    if database_url is None and environment is None:
        local_env_path = Path(dotenv_path) if dotenv_path is not None else Path(__file__).with_name(".env")
        database_url = dotenv_values(local_env_path).get("DATABASE_URL")

    if database_url is None or not database_url.strip():
        if required:
            raise RuntimeError("DATABASE_URL must be configured before database access")
        return None
    return normalize_database_url(database_url)


def create_database(database_url: str | URL) -> Database:
    url = normalize_database_url(database_url)
    options: dict[str, object] = {"pool_pre_ping": True}
    if url.get_backend_name() == "postgresql":
        # Two Gunicorn workers can each hold at most three pooled connections.
        options.update(pool_size=2, max_overflow=1, pool_timeout=10, pool_recycle=1800)

    engine = create_engine(url, **options)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    return Database(engine=engine, sessions=sessions)
