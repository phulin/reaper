* This codebase uses progressive disclosure to manage agent context.
  * For each package in src/ and each script in `scripts/`, maintain a `README.md` outlining each file's functionality and that of any subpackages.
  * Maintain an overall outline of packages in `CODEBASE.md`.
  * For the database, maintain a `SCHEMA.md` describing the schema concisely.
* Python packages are installed in `.venv`. Use `uv run` to run python code.
* After writing code, run `uv run ty check && uv run ruff check && uv run ruff format`.