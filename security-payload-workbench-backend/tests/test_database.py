from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from database import (
    create_database,
    database_url_from_environment,
    normalize_database_url,
)


BACKEND_ROOT = Path(__file__).resolve().parents[1]


def test_database_url_is_required_only_when_database_access_is_required():
    assert database_url_from_environment({}, required=False) is None
    with pytest.raises(RuntimeError, match="DATABASE_URL must be configured") as error:
        database_url_from_environment({}, required=True)
    assert "postgres" not in str(error.value).lower()


def test_database_url_loads_only_from_local_dotenv_when_process_value_is_absent(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    local_env = tmp_path / ".env"
    local_env.write_text(
        "DATABASE_URL=postgresql://db_user:p%40ss@localhost:5432/sentinelx\nOTHER_SECRET=ignored\n",
        encoding="utf-8",
    )

    url = database_url_from_environment(dotenv_path=local_env)

    assert url is not None
    assert url.drivername == "postgresql+psycopg"
    assert url.username == "db_user"
    assert url.password == "p@ss"


def test_process_environment_database_url_takes_precedence_over_dotenv(tmp_path, monkeypatch):
    local_env = tmp_path / ".env"
    local_env.write_text("DATABASE_URL=sqlite:///from-dotenv.sqlite\n", encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///from-process.sqlite")

    url = database_url_from_environment(dotenv_path=local_env)

    assert url is not None
    assert url.database == "from-process.sqlite"


def test_explicit_environment_mapping_does_not_read_local_dotenv(tmp_path, monkeypatch):
    local_env = tmp_path / ".env"
    local_env.write_text("DATABASE_URL=sqlite:///from-dotenv.sqlite\n", encoding="utf-8")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    assert database_url_from_environment({}, required=False, dotenv_path=local_env) is None


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_database_url_is_rejected(value):
    with pytest.raises(RuntimeError, match="DATABASE_URL must be configured"):
        database_url_from_environment({"DATABASE_URL": value})


def test_invalid_database_url_error_does_not_echo_the_value():
    secret_like_value = "not a valid database URL with secret"
    with pytest.raises(ValueError, match="DATABASE_URL is invalid") as error:
        normalize_database_url(secret_like_value)
    assert secret_like_value not in str(error.value)


@pytest.mark.parametrize(
    "value",
    [
        "postgres://db_user:p%40ss@db.example.test:5432/sentinelx",
        "postgresql://db_user:p%40ss@db.example.test:5432/sentinelx",
    ],
)
def test_postgresql_urls_are_normalized_to_psycopg(value):
    normalized = normalize_database_url(value)
    assert normalized.drivername == "postgresql+psycopg"
    assert normalized.username == "db_user"
    assert normalized.password == "p@ss"
    assert "p%40ss" not in normalized.render_as_string(hide_password=True)


def test_other_sqlalchemy_provider_urls_remain_provider_agnostic():
    normalized = normalize_database_url("sqlite+pysqlite:///:memory:")
    assert normalized.drivername == "sqlite+pysqlite"


def test_engine_and_session_factory_connect_to_sqlite():
    database = create_database("sqlite:///:memory:")
    try:
        with database.sessions() as session:
            assert session.execute(text("SELECT 1")).scalar_one() == 1
        assert database.sessions.kw["bind"] is database.engine
    finally:
        database.dispose()


def test_postgresql_engine_uses_a_small_lazy_connection_pool():
    database = create_database("postgresql://db_user:secret@db.example.test/sentinelx")
    try:
        assert database.engine.pool.size() == 2
        assert database.engine.pool._max_overflow == 1
        assert database.engine.pool._pre_ping is True
    finally:
        database.dispose()


def test_initial_migration_is_empty_and_repeatable(tmp_path, monkeypatch):
    database_file = tmp_path / "migration-test.sqlite"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database_file.as_posix()}")
    config = Config(str(BACKEND_ROOT / "alembic.ini"))

    command.upgrade(config, "head")
    command.upgrade(config, "head")

    database = create_database(f"sqlite:///{database_file.as_posix()}")
    try:
        assert inspect(database.engine).get_table_names() == ["alembic_version"]
        with database.engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "20261005_0001"
    finally:
        database.dispose()
