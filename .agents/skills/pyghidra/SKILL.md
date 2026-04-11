---
name: pyghidra
description: Use when writing Python scripts that read disassembly, read decompilation output, or modify Ghidra program state using PyGhidra.
---

# PyGhidra Skill

## Workflow Role

- Treat Ghidra as the live source of truth for an analysis run.
- The primary objective is to name every function, parameter, and local variable visible in the decompiler output.
- Subagents should not write to the project directly unless the main task explicitly says they own the Ghidra mutation step.
- Prefer having subagents emit JSON findings and then having the main agent review and apply them with `scripts/apply_analysis_json_to_ghidra.py`.
- Use Ghidra comments for annotations that need to persist with the program, but treat comments and types as secondary to naming coverage.

## Setup

For scripts that mutate the Ghidra database, open the program through PyGhidra's normal project/program context:

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

For read-only scripts, open the Ghidra project read-only. PyGhidra's
`open_project()` wrapper does not currently expose this option; use the
underlying Ghidra project manager:

```python
import pyghidra


def open_read_only_project(project_path, project_name):
    from ghidra.framework.model import ProjectLocator
    from ghidra.pyghidra import PyGhidraProjectManager

    project_locator = ProjectLocator(str(project_path), project_name)
    project_manager = PyGhidraProjectManager()
    return project_manager.openProject(project_locator, True, False)


pyghidra.start()
project = open_read_only_project("/path/to/project_dir", "project_name")
with pyghidra.program_context(project, "/program_name") as program:
    # read-only inspection here
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

## Getting Disassembly

See [examples/disassemble.py](examples/disassemble.py).

- `program.getListing()` returns the listing used to inspect instructions and data
- `listing.getInstructionAt(address)` gets one instruction at an address
- `listing.getInstructions(address_set_view, True)` iterates instructions forward over a function body or address set
- Use `instruction.getFallThrough()` and `instruction.getReferencesFrom()` when following control flow beyond a simple sequential dump

## Iterating Functions

See [examples/iterate_functions.py](examples/iterate_functions.py).

- `func_mgr.getFunctions(True)` iterates all functions
- `func_mgr.getFunctionContaining(address_space.getAddress(0x1234))` finds a function by address

## Renaming Variables

See [examples/rename_variables.py](examples/rename_variables.py).

- Iterate `hf.getLocalSymbolMap().getSymbols()` to inspect candidate locals, including their storage via `symbol.getStorage()`
- Call `HighFunctionDBUtil.updateDBVariable(sym, new_name, new_type, SourceType.USER_DEFINED)` inside a transaction
- After any write, the existing `HighFunction` is **stale** — re-decompile to get updated names
- Prefer spending effort on naming unnamed or weakly named locals before adding extra commentary
- When emitting JSON artifacts or any other deferred rename plan, identify locals by storage string rather than the current symbol name; names are expected to change during incremental cleanup, but storage stays stable

## Renaming Parameters

See [examples/rename_parameters.py](examples/rename_parameters.py).

- Use `sym_map.getParamSymbol(i)` to access parameters by index
- Use `HighFunctionDBUtil.commitParamsToDatabase()` to commit all params at once
- Parameter naming is part of the core completion criterion, not an optional cleanup step

## Committing All Local Names

See [examples/commit_locals.py](examples/commit_locals.py).

- `HighFunctionDBUtil.commitLocalNamesToDatabase(hf, SourceType.USER_DEFINED)` persists all local variable names
- Use this when it helps close naming coverage quickly after you have validated the local names

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
- For automation and artifact-driven workflows, prefer `--storage`; name-based selection is mainly a convenience for one-off interactive use

## Looking Up Existing Data Types

See [examples/lookup_datatypes.py](examples/lookup_datatypes.py).

- Look up by path: `dtm.getDataType("/CategoryName/TypeName")`
- Search by name: `dtm.findDataTypes("MyStruct", results)`
- Built-in primitives (`IntegerDataType`, `PointerDataType`, etc.) can be imported directly from `ghidra.program.model.data`

## Important Caveats

- All program mutations require a `pyghidra.transaction(program, ...)` context.
- Use `PyGhidraProjectManager().openProject(project_locator, True, False)` for scripts that only inspect disassembly, decompilation, functions, symbols, data types, or bytes.
- After any `HighFunctionDBUtil` write, the `HighFunction` object is **stale** — call `decompileFunction()` again to get fresh results.
- `open_program()` is deprecated; use `open_project()` + `program_context()` instead.
- `HighFunctionDBUtil.updateDBVariable()` can flush **all** parameters if a type inconsistency is detected (not just the one you renamed).
- `DataTypeConflictHandler.REPLACE_HANDLER` replaces an existing type with the same name; use `DEFAULT_HANDLER` to keep the existing one.
