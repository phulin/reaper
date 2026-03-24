# reaper.db package

Database layer for Reaper, built on SQLAlchemy and Alembic.

## Files

- `__init__.py`: re-exports the primary database types and helpers.
- `base.py`: declarative base used by all ORM models.
- `config.py`: environment-driven database settings, including `REAPER_DATABASE_URL`.
- `models.py`: ORM models for functions, annotations, call graph edges, modules, and data types.
- `session.py`: engine and session-factory helpers.

## Subpackages

- `migrations/`: Alembic environment and revision history for schema changes.

## Notes

- The schema targets PostgreSQL.
- Vector search uses the `pgvector` extension.
- Migration entrypoints are typically run through `scripts/migrate.py`.
