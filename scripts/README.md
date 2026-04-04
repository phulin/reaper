# scripts

Operational entrypoints and analysis helpers.

## Files

- `apply_analysis_json_to_ghidra.py`: applies a reviewed JSON analysis artifact into a Ghidra project. It is the default handoff point for synthesized subagent output, applies local-variable renames by storage (with legacy name-based fallback), and can create recovered structs plus function comments.
- `create_ghidra_project.py`: creates a Ghidra project directory, imports a binary with auto-detection, and runs Ghidra's auto-analysis. Project path defaults to `analysis-<sha256[:10]>/` and project name defaults to `<sha256[:10]>`. Outputs JSON with the project path and imported program names.
- `decompile_ghidra_functions.py`: decompiles selected function entrypoints from an existing Ghidra project and prints JSON containing recovered pseudocode and optional signatures.
- `export_ghidra_function_bundle.py`: exports a selected function list from a Ghidra program into one JSON bundle with signatures, pseudocode, parameters, and local-symbol details for offline review or subagent handoff.
- `inventory_ghidra_functions.py`: decompiles every function in a Ghidra program and emits JSON summarizing function, parameter, and local naming coverage so chunking can focus on remaining auto-generated symbols.
- `merge_analysis_json.py`: merges multiple reviewed or subagent-generated analysis JSON files into one deterministic artifact keyed by function address and data-type path/name.
- `split_ghidra_variable.py`: lists local variables whose `HighVariable`s contain multiple merge groups and can split one merge group into a new decompiler variable using `HighFunction.splitOutMergeGroup()`. Selection can be driven by symbol name or storage location, with optional representative and PC-address filters. The script can also rename the original and split variables and persist the result back into the Ghidra project.
