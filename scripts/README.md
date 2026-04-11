# scripts

Operational entrypoints and analysis helpers.

## Classification

Generic/reusable scripts are the PyGhidra project, decompile, inventory, bundle, JSON artifact, xref, immediate-scan, function-creation, split-variable, and NE resource extraction helpers. Repo-specific scripts are the SimTower naming/type application scripts, condo/gate/blocker/VIP investigation waves, resource scripts with SimTower labels, and scripts that hard-code recovered addresses, segment IDs, object-family IDs, project paths, or `SIMTOWER.EX_`.

## Files

- `apply_analysis_json_to_ghidra.py`: applies a reviewed JSON analysis artifact into a Ghidra project. It is the default handoff point for synthesized subagent output, applies local-variable renames by storage (with legacy name-based fallback), and can create recovered structs plus function comments.
- `create_ghidra_project.py`: creates a Ghidra project directory, imports a binary with auto-detection, and runs Ghidra's auto-analysis. Project path defaults to `analysis-<sha256[:10]>/` and project name defaults to `<sha256[:10]>`. Outputs JSON with the project path and imported program names.
- `create_ghidra_functions.py`: disassembles specified addresses and creates functions at those entrypoints in an existing Ghidra project, skipping any address that already has a function.
- `create_ghidra_functions_from_prologues.py`: scans decoded 16-bit instructions for the `mov ax,ss; nop; inc bp; push bp; mov bp,sp` and `inc bp; push bp; mov bp,sp` prologues, deduplicates overlapping matches, and creates functions only for candidates that are still outside any defined function.
- `decompile_ghidra_functions.py`: decompiles selected function entrypoints from an existing Ghidra project in read-only mode and prints JSON containing recovered pseudocode and optional signatures.
- `define_service_facility_types.py`: creates Ghidra data types for the shared commercial-venue sidecar records and the restaurant, fast-food, and retail-shop bucket tables in `SIMTOWER.EX_`, applies them to the corresponding global pointer slots, and renames nearby helper functions.
- `define_runtime_entity_type.py`: creates the `RuntimeEntityRecord` data type for the core 1228/1218 mechanics paths, including the queued-route and timed-state fields recovered so far, and applies it to `g_runtime_entity_table` in `SIMTOWER.EX_`.
- `define_entertainment_link_type.py`: creates the `EntertainmentLinkRecord` data type for the 16-entry entertainment/event link table used by the `1188` subsystem and applies it to the recovered global table in `SIMTOWER.EX_`.
- `define_placed_object_type.py`: creates the `PlacedObjectRecord` data type for the 0x12-byte per-floor placed-object records recovered from the archive/object-rebuild paths in `SIMTOWER.EX_`.
- `define_route_queue_types.py`: creates recovered route-layer data types for the tower-direction ring buffers and per-unit active-route tables used by the `1218` request/queue subsystem.
- `define_route_support_types.py`: creates recovered route-support data types for the 24 carrier-record pointers, the 64 raw stair/escalator segment entries, the derived lobby/sky-lobby special-link records, and the 16-entry transfer-group cache used by the lower `11b8` route scorer.
- `define_floor_object_table_types.py`: creates recovered floor-object handle and floor-local object-blob data types, including the 6-byte header, `PlacedObjectRecord[150]`, and 150-entry subtype map layout; applies the 120-entry `g_floor_object_tables` array at `0x1288c022`; and names the helpers that allocate and rebuild floor subtype indices.
- `find_ghidra_address_xrefs.py`: looks up exact addresses in a Ghidra program in read-only mode and emits all incoming references plus nearby symbol/data metadata. Useful when packed string tables or non-standard data definitions defeat substring-based string xref search.
- `export_ghidra_function_bundle.py`: exports a selected function list from a Ghidra program into one JSON bundle with signatures, pseudocode, parameters, and local-symbol details for offline review or subagent handoff.
- `extract_ne_resources.py`: lists or extracts arbitrary resources from a Windows NE executable, with filters by resource type/name and id plus optional 16-bit word swapping for payloads stored in opposite byte order.
- `find_ghidra_string_xrefs.py`: searches defined strings in a Ghidra program by case-insensitive substring in read-only mode and emits the cross-references back to containing functions. Useful for tracing report labels, gameplay messages, and other mechanic-relevant strings into code.
- `inventory_ghidra_functions.py`: decompiles every function in a Ghidra program and emits JSON summarizing function, parameter, and local naming coverage so chunking can focus on remaining auto-generated symbols.
- `merge_analysis_json.py`: merges multiple reviewed or subagent-generated analysis JSON files into one deterministic artifact keyed by function address and data-type path/name.
- `rebase_analysis_json_by_storage.py`: rebases stale local-variable rename artifacts onto a current Ghidra function bundle by matching decompiler locals through storage strings instead of names.
- `scan_operand_immediate.py`: scans each instruction operand in a Ghidra program for exact immediate values and emits matching instructions, containing functions, and operand metadata as JSON.
- `extract_ne_bitmaps.py`: extracts embedded `RT_BITMAP` resources from the decompressed `SIMTOWER.EX_`, rebuilds BMP file headers, converts them to PNG via `sips`, groups facility-preview resources into per-type ranges, assigns canonical filenames for those ranges, and writes a manifest with resource IDs, dimensions, and recovered naming hints.
- `rename_service_facility_globals.py`: renames the tuning globals used by the restaurant, fast-food, and retail-shop commercial-venue subsystem, including capacity limits, service durations, thresholds, derived state-code tables, and the bucket-table globals.
- `rename_entertainment_globals.py`: renames the `1188` entertainment/event globals, including the 16-entry link table, the active-link counter, and the attendance-threshold and income-rate tier constants.
- `split_ghidra_variable.py`: lists local variables whose `HighVariable`s contain multiple merge groups and can split one merge group into a new decompiler variable using `HighFunction.splitOutMergeGroup()`. Selection can be driven by symbol name or storage location, with optional representative and PC-address filters. The script can also rename the original and split variables and persist the result back into the Ghidra project.
