# scripts

Operational entrypoints and analysis helpers.

## Files

- `apply_analysis_json_to_ghidra.py`: applies a reviewed JSON analysis artifact into a Ghidra project. It is the default handoff point for synthesized subagent output and can create recovered structs plus function comments.
- `create_ghidra_project.py`: creates a Ghidra project directory, imports a binary with auto-detection, and runs Ghidra's auto-analysis. Project path defaults to `analysis-<sha256[:10]>/` and project name defaults to `<sha256[:10]>`. Outputs JSON with the project path and imported program names.
- `decompile_ghidra_functions.py`: decompiles selected function entrypoints from an existing Ghidra project and prints JSON containing recovered pseudocode and optional signatures.
- `split_ghidra_variable.py`: lists local variables whose `HighVariable`s contain multiple merge groups and can split one merge group into a new decompiler variable using `HighFunction.splitOutMergeGroup()`. Selection can be driven by symbol name or storage location, with optional representative and PC-address filters. The script can also rename the original and split variables and persist the result back into the Ghidra project.
