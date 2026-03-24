# scripts

Operational entrypoints and analysis helpers.

## Files

- `migrate.py`: runs Alembic migrations against the configured Reaper database.
- `import_angr_functions.py`: upserts a target row for a binary, runs `angr` CFG recovery, and persists recovered functions plus call-graph edges into the database.
- `create_ghidra_project.py`: creates a Ghidra project directory, imports a binary with auto-detection, and runs Ghidra's auto-analysis. Project path defaults to `analysis-<sha256[:10]>/` and project name defaults to `<sha256[:10]>`. Outputs JSON with the project path and imported program names.
