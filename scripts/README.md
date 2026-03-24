# scripts

Operational entrypoints and analysis helpers.

## Files

- `migrate.py`: runs Alembic migrations against the configured Reaper database.
- `import_angr_functions.py`: upserts a target row for a binary, runs `angr` CFG recovery, and persists recovered functions plus call-graph edges into the database.
- `create_ghidra_project.py`: creates a Ghidra project directory, imports a binary with auto-detection, and runs Ghidra's auto-analysis. Project path defaults to `analysis-<sha256[:10]>/` and project name defaults to `<sha256[:10]>`. Outputs JSON with the project path and imported program names.
- `apply_analysis_results.py`: applies manually recovered structs, global names, parameter names, local variable names, and reconstructed signatures to both the SQL database and the matching Ghidra project for a hard-coded target binary.
- `split_ghidra_variable.py`: lists local variables whose `HighVariable`s contain multiple merge groups and can split one merge group into a new decompiler variable using `HighFunction.splitOutMergeGroup()`. Selection can be driven by symbol name or storage location, with optional representative and PC-address filters. The script can also rename the original and split variables and persist the result back into the Ghidra project.
