# Reaper

Reverse Engineering through Automated Prompt Execution and Recording.

## Layout

- `src/reaper/`: main Python package. See [src/reaper/README.md](/Users/phulin/Documents/Projects/reaper/src/reaper/README.md).
- `scripts/`: operational entrypoints and developer helpers.
- `docs/`: project notes and supporting documentation.
- `main.py`: minimal top-level entrypoint stub.
- `pyproject.toml`: project metadata and dependencies.

## Database

The ORM and migrations live under `src/reaper/db/`.

- SQLAlchemy models define the reverse-engineering schema.
- Alembic revisions manage schema changes.
- `scripts/migrate.py` is the local migration wrapper.

## Common Commands

```bash
uv sync
uv run python scripts/migrate.py upgrade head
uv run python scripts/migrate.py history
```
