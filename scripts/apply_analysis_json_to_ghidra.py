from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

import pyghidra


def default_project_name(project_path: Path) -> str:
    dir_name = project_path.name
    if dir_name.startswith("analysis-"):
        return dir_name[len("analysis-") :]
    return dir_name


def load_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise SystemExit("ERROR: analysis artifact must be a JSON object")
    return payload


def parse_address(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"Unsupported address value: {value!r}")


def open_program(project_path: Path, project_name: str, program_name: str | None):
    project = pyghidra.open_project(str(project_path), project_name)
    root = project.getProjectData().getRootFolder()
    files = list(root.getFiles())
    if not files:
        raise SystemExit("ERROR: no programs found in the Ghidra project root")

    if program_name is None:
        if len(files) > 1:
            available = ", ".join(sorted(file.getName() for file in files))
            raise SystemExit(
                "ERROR: multiple programs in project root; specify --program-name "
                f"({available})"
            )
        return files[0]

    for domain_file in files:
        if domain_file.getName() == program_name:
            return domain_file

    available = ", ".join(sorted(file.getName() for file in files))
    raise SystemExit(
        f"ERROR: program '{program_name}' not found in project root; available: "
        f"{available}"
    )


def build_annotation_comment(summary: str | None, annotations: list[str]) -> str | None:
    sections: list[str] = []
    if summary:
        sections.append(summary.strip())
    if annotations:
        rendered = "\n".join(
            f"- {note.strip()}" for note in annotations if note.strip()
        )
        if rendered:
            sections.append(f"Notes:\n{rendered}")
    if not sections:
        return None
    return "\n\n".join(sections)


def coerce_notes(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(note) for note in value if str(note).strip()]


def lookup_high_symbol_by_name(high_function: Any, current_name: str) -> Any | None:
    matches = [
        symbol
        for symbol in high_function.getLocalSymbolMap().getSymbols()
        if not symbol.isParameter() and symbol.getName() == current_name
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def lookup_high_symbol_by_storage(high_function: Any, storage: str) -> Any | None:
    matches = [
        symbol
        for symbol in high_function.getLocalSymbolMap().getSymbols()
        if not symbol.isParameter() and str(symbol.getStorage()) == storage
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def collect_taken_local_names(function: Any, high_function: Any) -> set[str]:
    names = {
        function.getParameter(i).getName()
        for i in range(function.getParameterCount())
        if function.getParameter(i).getName()
    }
    names.update(
        symbol.getName()
        for symbol in high_function.getLocalSymbolMap().getSymbols()
        if not symbol.isParameter() and symbol.getName()
    )
    return names


def collect_taken_parameter_names(high_function: Any) -> set[str]:
    symbol_map = high_function.getLocalSymbolMap()
    return {
        symbol_map.getParamSymbol(i).getName()
        for i in range(symbol_map.getNumParams())
        if symbol_map.getParamSymbol(i) is not None
        and symbol_map.getParamSymbol(i).getName()
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Apply a synthesized JSON analysis artifact into a Ghidra project. "
            "This is intended for main-agent use after reviewing subagent outputs."
        )
    )
    parser.add_argument("--analysis-json", type=Path, required=True)
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument(
        "--project-name",
        default=None,
        help="Ghidra project name. Defaults to the project directory stem.",
    )
    parser.add_argument(
        "--program-name",
        default=None,
        help="Program name in the project root. Required if the root has multiple programs.",
    )
    args = parser.parse_args()

    payload = load_payload(args.analysis_json.resolve())
    project_path = args.project_path.resolve()
    project_name = args.project_name or default_project_name(project_path)
    program_name = args.program_name or payload.get("program_name")

    pyghidra.start()

    from ghidra.program.model.data import (  # ty:ignore[unresolved-import]
        BooleanDataType,
        ByteDataType,
        CategoryPath,
        CharDataType,
        DataTypeConflictHandler,
        DoubleDataType,
        FloatDataType,
        IntegerDataType,
        LongDataType,
        PointerDataType,
        ShortDataType,
        StructureDataType,
        UnsignedIntegerDataType,
        UnsignedLongDataType,
        UnsignedShortDataType,
        VoidDataType,
    )
    from ghidra.app.decompiler import DecompInterface  # ty:ignore[unresolved-import]
    from ghidra.program.model.listing import (  # ty:ignore[unresolved-import]
        CommentType,
        Program,
    )
    from ghidra.program.model.pcode import HighFunctionDBUtil  # ty:ignore[unresolved-import]
    from ghidra.program.model.symbol import SourceType  # ty:ignore[unresolved-import]
    from java.lang import Object  # ty:ignore[unresolved-import]

    builtin_types = {
        "bool": BooleanDataType.dataType,
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "double": DoubleDataType.dataType,
        "float": FloatDataType.dataType,
        "int16_t": ShortDataType.dataType,
        "int32_t": IntegerDataType.dataType,
        "int64_t": LongDataType.dataType,
        "int8_t": ByteDataType.dataType,
        "uint16_t": UnsignedShortDataType.dataType,
        "uint32_t": UnsignedIntegerDataType.dataType,
        "uint64_t": UnsignedLongDataType.dataType,
        "uint8_t": ByteDataType.dataType,
        "void": VoidDataType.dataType,
    }

    def resolve_type(type_name: str, resolved_types: dict[str, Any]) -> Any:
        stripped = type_name.strip()
        if stripped.endswith("*"):
            pointee = resolve_type(stripped[:-1], resolved_types)
            return PointerDataType(pointee)
        if stripped in resolved_types:
            return resolved_types[stripped]
        if stripped in builtin_types:
            return builtin_types[stripped]
        return PointerDataType(VoidDataType.dataType)

    domain_file = open_program(project_path, project_name, program_name)
    consumer = Object()
    program = cast(
        Program,
        domain_file.getDomainObject(consumer, True, False, pyghidra.task_monitor()),
    )

    renamed = 0
    renamed_params = 0
    renamed_locals = 0
    renamed_globals = 0
    plate_comments = 0
    repeatable_comments = 0
    created_types = 0
    missing_functions: list[str] = []
    missing_globals: list[str] = []
    missing_locals: list[str] = []
    skipped_conflicts: list[str] = []

    try:
        with pyghidra.transaction(program, "apply_analysis_json_to_ghidra"):
            dtm = program.getDataTypeManager()
            resolved_types: dict[str, Any] = {}
            decomp = DecompInterface()
            decomp.openProgram(program)

            try:
                for type_entry in payload.get("data_types", []):
                    if not isinstance(type_entry, dict):
                        continue
                    if type_entry.get("kind") != "struct":
                        continue

                    name = type_entry.get("name")
                    if not isinstance(name, str) or not name:
                        continue

                    category = type_entry.get("path", "/reaper")
                    size_bytes = int(type_entry.get("size_bytes", 0))
                    struct = StructureDataType(CategoryPath(category), name, size_bytes)
                    for field in type_entry.get("fields", []):
                        if not isinstance(field, dict):
                            continue
                        field_name = str(field.get("name", "field"))
                        field_type = resolve_type(
                            str(field.get("type", "void*")), resolved_types
                        )
                        field_offset = int(field.get("offset", 0))
                        field_comment = str(field.get("comment", ""))
                        field_length = field_type.getLength()
                        if field_length <= 0:
                            field_length = 1
                        struct.replaceAtOffset(
                            field_offset,
                            field_type,
                            field_length,
                            field_name,
                            field_comment,
                        )

                    resolved = dtm.resolve(
                        struct, DataTypeConflictHandler.REPLACE_HANDLER
                    )
                    resolved_types[name] = resolved
                    resolved_types[f"{category}/{name}"] = resolved
                    created_types += 1

                listing = program.getListing()
                symbol_table = program.getSymbolTable()
                function_manager = program.getFunctionManager()
                address_space = program.getAddressFactory().getDefaultAddressSpace()

                for global_entry in payload.get("globals", []):
                    if not isinstance(global_entry, dict):
                        continue
                    try:
                        address = parse_address(global_entry["address"])
                    except (KeyError, TypeError, ValueError):
                        continue
                    addr = address_space.getAddress(address)
                    proposed_name = global_entry.get("name")
                    if isinstance(proposed_name, str) and proposed_name:
                        symbol_table.createLabel(
                            addr, proposed_name, SourceType.USER_DEFINED
                        )
                        renamed_globals += 1
                    comment = global_entry.get("comment")
                    if isinstance(comment, str) and comment.strip():
                        code_unit = listing.getCodeUnitAt(addr)
                        if code_unit is not None:
                            code_unit.setComment(CommentType.PLATE, comment)
                            plate_comments += 1

                for function_entry in payload.get("functions", []):
                    if not isinstance(function_entry, dict):
                        continue
                    try:
                        address = parse_address(function_entry["address"])
                    except (KeyError, TypeError, ValueError):
                        continue

                    function = function_manager.getFunctionAt(
                        address_space.getAddress(address)
                    )
                    if function is None:
                        missing_functions.append(hex(address))
                        continue

                    proposed_name = function_entry.get("name")
                    if (
                        isinstance(proposed_name, str)
                        and proposed_name
                        and function.getName() != proposed_name
                    ):
                        function.setName(proposed_name, SourceType.USER_DEFINED)
                        renamed += 1

                    parameters = function_entry.get("parameters", [])
                    locals_payload = function_entry.get("locals", [])
                    parameters_list = parameters if isinstance(parameters, list) else []
                    locals_list = (
                        locals_payload if isinstance(locals_payload, list) else []
                    )
                    if (isinstance(parameters, list) and parameters) or (
                        isinstance(locals_payload, list) and locals_payload
                    ):
                        result = decomp.decompileFunction(
                            function, 90, pyghidra.task_monitor()
                        )
                        if result.decompileCompleted():
                            high_function = result.getHighFunction()
                            symbol_map = high_function.getLocalSymbolMap()
                            if parameters_list:
                                for param_entry in parameters_list:
                                    if not isinstance(param_entry, dict):
                                        continue
                                    ordinal = param_entry.get("ordinal")
                                    new_name = param_entry.get("name")
                                    if not isinstance(ordinal, int) or not isinstance(
                                        new_name, str
                                    ):
                                        continue
                                    if (
                                        ordinal < 0
                                        or ordinal >= symbol_map.getNumParams()
                                    ):
                                        continue
                                    symbol = symbol_map.getParamSymbol(ordinal)
                                    if symbol is None:
                                        continue
                                    taken_param_names = collect_taken_parameter_names(
                                        high_function
                                    )
                                    if (
                                        new_name != symbol.getName()
                                        and new_name in taken_param_names
                                    ):
                                        skipped_conflicts.append(
                                            f"{hex(address)}:param[{ordinal}]->{new_name}"
                                        )
                                        continue
                                    type_name = param_entry.get("type")
                                    new_type = (
                                        resolve_type(type_name, resolved_types)
                                        if isinstance(type_name, str)
                                        and type_name.strip()
                                        else symbol.getDataType()
                                    )
                                    if symbol.getName() != new_name or (
                                        isinstance(type_name, str) and type_name.strip()
                                    ):
                                        try:
                                            HighFunctionDBUtil.updateDBVariable(
                                                symbol,
                                                new_name,
                                                new_type,
                                                SourceType.USER_DEFINED,
                                            )
                                        except Exception:
                                            skipped_conflicts.append(
                                                f"{hex(address)}:param[{ordinal}]->{new_name}"
                                            )
                                            continue
                                        renamed_params += 1
                                        refreshed = decomp.decompileFunction(
                                            function, 90, pyghidra.task_monitor()
                                        )
                                        if refreshed.decompileCompleted():
                                            high_function = refreshed.getHighFunction()
                                            symbol_map = (
                                                high_function.getLocalSymbolMap()
                                            )
                            for local_entry in locals_list:
                                if not isinstance(local_entry, dict):
                                    continue
                                storage = local_entry.get("storage")
                                current_name = local_entry.get("current_name")
                                new_name = local_entry.get("name")
                                if not isinstance(new_name, str):
                                    continue
                                if not isinstance(storage, str) and not isinstance(
                                    current_name, str
                                ):
                                    continue
                                identifier = (
                                    storage
                                    if isinstance(storage, str)
                                    else cast(str, current_name)
                                )
                                symbol = None
                                if isinstance(storage, str):
                                    symbol = lookup_high_symbol_by_storage(
                                        high_function, storage
                                    )
                                if symbol is None and isinstance(current_name, str):
                                    symbol = lookup_high_symbol_by_name(
                                        high_function, current_name
                                    )
                                if symbol is None:
                                    missing_locals.append(
                                        f"{hex(address)}:{identifier}->{new_name}"
                                    )
                                    continue
                                if not isinstance(new_name, str):
                                    continue
                                taken_names = collect_taken_local_names(
                                    function, high_function
                                )
                                if (
                                    new_name != symbol.getName()
                                    and new_name in taken_names
                                ):
                                    skipped_conflicts.append(
                                        f"{hex(address)}:{identifier}->{new_name}"
                                    )
                                    continue
                                type_name = local_entry.get("type")
                                new_type = (
                                    resolve_type(type_name, resolved_types)
                                    if isinstance(type_name, str) and type_name.strip()
                                    else symbol.getDataType()
                                )
                                if symbol.getName() != new_name or (
                                    isinstance(type_name, str) and type_name.strip()
                                ):
                                    try:
                                        HighFunctionDBUtil.updateDBVariable(
                                            symbol,
                                            new_name,
                                            new_type,
                                            SourceType.USER_DEFINED,
                                        )
                                    except Exception:
                                        skipped_conflicts.append(
                                            f"{hex(address)}:{identifier}->{new_name}"
                                        )
                                        continue
                                    renamed_locals += 1
                                    refreshed = decomp.decompileFunction(
                                        function, 90, pyghidra.task_monitor()
                                    )
                                    if refreshed.decompileCompleted():
                                        high_function = refreshed.getHighFunction()
                        else:
                            missing_locals.append(
                                f"{hex(address)}:<decompile failed for locals>"
                            )

                    summary = function_entry.get("summary")
                    if not isinstance(summary, str):
                        summary = None

                    annotations = coerce_notes(function_entry.get("annotations", []))

                    plate_comment = (
                        function_entry.get("plate_comment")
                        if isinstance(function_entry.get("plate_comment"), str)
                        else summary
                    )
                    repeatable_comment = (
                        function_entry.get("repeatable_comment")
                        if isinstance(function_entry.get("repeatable_comment"), str)
                        else build_annotation_comment(summary, annotations)
                    )

                    if summary:
                        function.setComment(summary)

                    code_unit = listing.getCodeUnitAt(function.getEntryPoint())
                    if code_unit is None:
                        continue
                    if isinstance(plate_comment, str) and plate_comment.strip():
                        code_unit.setComment(CommentType.PLATE, plate_comment)
                        plate_comments += 1
                    if (
                        isinstance(repeatable_comment, str)
                        and repeatable_comment.strip()
                    ):
                        code_unit.setComment(CommentType.REPEATABLE, repeatable_comment)
                        repeatable_comments += 1
            finally:
                decomp.dispose()

        program.getDomainFile().save(pyghidra.task_monitor())
    finally:
        program.release(consumer)

    summary = (
        f"Renamed {renamed} functions, {renamed_globals} globals, {renamed_params} parameters, "
        f"{renamed_locals} locals, applied {plate_comments} plate comments, "
        f"{repeatable_comments} repeatable comments, and synced {created_types} data types."
    )
    if missing_functions:
        summary += " Missing functions: " + ", ".join(sorted(missing_functions))
    if missing_globals:
        summary += " Missing globals: " + ", ".join(sorted(missing_globals))
    if missing_locals:
        summary += " Missing locals: " + ", ".join(sorted(missing_locals))
    if skipped_conflicts:
        summary += " Skipped conflicts: " + ", ".join(sorted(skipped_conflicts))
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
