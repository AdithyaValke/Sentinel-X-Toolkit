from alembic import context
from sqlalchemy.engine import Connection

from database import Base, create_database, database_url_from_environment
import models  # noqa: F401 -- register model metadata for Alembic autogeneration


config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = database_url_from_environment(required=True)
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = database_url_from_environment(required=True)
    database = create_database(url)
    try:
        with database.engine.connect() as connection:
            do_run_migrations(connection)
    finally:
        database.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
