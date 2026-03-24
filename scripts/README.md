# scripts

Operational entrypoints and analysis helpers.

## Files

- `migrate.py`: runs Alembic migrations against the configured Reaper database.
- `import_angr_functions.py`: upserts a target row for a binary, runs `angr` CFG recovery, and persists recovered functions plus call-graph edges into the database.
