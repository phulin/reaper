---
name: pyghidra-decompiler
description: Use when writing Python scripts that read or modify decompilation output using PyGhidra.
---

# PyGhidra Decompiler Skill

## Workflow Role

- Treat Ghidra as the live source of truth for an analysis run.
- Subagents should not write to the project directly unless the main task explicitly says they own the Ghidra mutation step.
- Prefer having subagents emit JSON findings and then having the main agent review and apply them with
  [`/Users/phulin/Documents/Projects/reaper/scripts/apply_analysis_json_to_ghidra.py`](/Users/phulin/Documents/Projects/reaper/scripts/apply_analysis_json_to_ghidra.py).
- Use Ghidra comments for annotations that need to persist with the program.

## Setup

```python
import pyghidra

# Start the JVM (once per process)
pyghidra.start()

# Open a project and program
project = pyghidra.open_project("/path/to/project_dir", "project_name")
with pyghidra.program_context(project, "/program_name") as program:
    # work with program here
    pass
```

All writes to the program state **must** be wrapped in a transaction:

```python
with pyghidra.transaction(program, "Rename variables"):
    # any writes here
    pass
```

## Getting Decompiled Output

See [examples/decompile.py](examples/decompile.py).

- Create a `DecompInterface`, call `openProgram()`, then `decompileFunction(func, timeout, monitor)`
- `result.getDecompiledFunction().getC()` returns the C pseudocode as a string
- `result.getHighFunction()` returns the structured `HighFunction` representation
- Call `decomp.dispose()` when done

## Iterating Functions

See [examples/iterate_functions.py](examples/iterate_functions.py).

- `func_mgr.getFunctions(True)` iterates all functions
- `func_mgr.getFunctionContaining(toAddr(0x1234))` finds a function by address

## Renaming Variables

See [examples/rename_variables.py](examples/rename_variables.py).

- Iterate `hf.getLocalSymbolMap().getSymbols()` to find a symbol by name
- Call `HighFunctionDBUtil.updateDBVariable(sym, new_name, new_type, SourceType.USER_DEFINED)` inside a transaction
- After any write, the existing `HighFunction` is **stale** — re-decompile to get updated names

## Renaming Parameters

See [examples/rename_parameters.py](examples/rename_parameters.py).

- Use `sym_map.getParamSymbol(i)` to access parameters by index
- Use `HighFunctionDBUtil.commitParamsToDatabase()` to commit all params at once

## Committing All Local Names

See [examples/commit_locals.py](examples/commit_locals.py).

- `HighFunctionDBUtil.commitLocalNamesToDatabase(hf, SourceType.USER_DEFINED)` persists all local variable names

## Creating Data Structures

See [examples/create_struct.py](examples/create_struct.py).

- Create with `StructureDataType("Name", 0, dtm)`, add fields with `.add(type, size, name, comment)`
- Resolve into the program with `dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER)`
- Use `REPLACE_HANDLER` to overwrite existing types; use `DEFAULT_HANDLER` to keep existing

## Applying a Data Type to a Variable

See [examples/apply_datatype.py](examples/apply_datatype.py).

- Retrieve a type with `dtm.getDataType("/MyStruct")` or use the `resolved` object from creation
- Apply with `HighFunctionDBUtil.updateDBVariable(sym, None, resolved_type, SourceType.USER_DEFINED)`

## Splitting Merged Decompiler Variables

When a decompiler local is really multiple lifetimes merged into one `HighVariable`, use
[`/Users/phulin/Documents/Projects/reaper/scripts/split_ghidra_variable.py`](/Users/phulin/Documents/Projects/reaper/scripts/split_ghidra_variable.py)
instead of hand-rolling the merge-group logic each time.

- The script lists locals that contain multiple merge groups.
- It can select a split target by symbol name or by storage location, with optional `--pc-address` and `--representative` filters.
- It uses `HighFunction.splitOutMergeGroup()` and can optionally rename both the original and split variables, then saves and re-decompiles to confirm persistence.
- Typical workflow: list candidates for a function first, then rerun with `--merge-group` plus either `--symbol-name` or `--storage`.

## Looking Up Existing Data Types

See [examples/lookup_datatypes.py](examples/lookup_datatypes.py).

- Look up by path: `dtm.getDataType("/CategoryName/TypeName")`
- Search by name: `dtm.findDataTypes("MyStruct", results)`
- Built-in primitives (`IntegerDataType`, `PointerDataType`, etc.) can be imported directly from `ghidra.program.model.data`

## Important Caveats

- All program mutations require a `pyghidra.transaction(program, ...)` context.
- After any `HighFunctionDBUtil` write, the `HighFunction` object is **stale** — call `decompileFunction()` again to get fresh results.
- `open_program()` is deprecated; use `open_project()` + `program_context()` instead.
- `HighFunctionDBUtil.updateDBVariable()` can flush **all** parameters if a type inconsistency is detected (not just the one you renamed).
- `DataTypeConflictHandler.REPLACE_HANDLER` replaces an existing type with the same name; use `DEFAULT_HANDLER` to keep the existing one.
