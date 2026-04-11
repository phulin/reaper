from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import pyghidra


AUTO_NAME_PATTERNS = (
    re.compile(r"^FUN_[0-9a-fA-F]+$"),
    re.compile(r"^thunk_FUN_[0-9a-fA-F]+$"),
    re.compile(r"^FID_conflict[:_].+"),
    re.compile(r"^(param|local|local_res|uStack|puStack|iStack|bStack|cStack)_"),
    re.compile(r"^[a-z]+Var\d+$"),
    re.compile(r"^extraout_.+"),
    re.compile(r"^au(Stack|Var).+"),
    re.compile(r"^in_[A-Z0-9_]+$"),
    re.compile(r"^unaff_.+"),
    re.compile(r"^UNRECOVERED_.+"),
)


def default_project_name(project_path: Path) -> str:
    dir_name = project_path.name
    if dir_name.startswith("analysis-"):
        return dir_name[len("analysis-") :]
    return dir_name


def open_project_read_only(project_path: Path, project_name: str):
    from ghidra.framework.model import ProjectLocator  # ty:ignore[unresolved-import]
    from ghidra.pyghidra import PyGhidraProjectManager  # ty:ignore[unresolved-import]

    project_locator = ProjectLocator(str(project_path), project_name)
    project_manager = PyGhidraProjectManager()
    return project_manager.openProject(project_locator, True, False)


def looks_auto_name(name: str) -> bool:
    return any(pattern.match(name) for pattern in AUTO_NAME_PATTERNS)


def collect_symbol_details(symbols: list[Any]) -> tuple[list[dict[str, Any]], int]:
    details: list[dict[str, Any]] = []
    auto_count = 0
    for symbol in symbols:
        name = symbol.getName()
        is_auto = looks_auto_name(name)
        if is_auto:
            auto_count += 1
        details.append(
            {
                "name": name,
                "data_type": str(symbol.getDataType()),
                "auto_name": is_auto,
                "storage": str(symbol.getStorage()),
                "category_index": int(symbol.getCategoryIndex()),
            }
        )
    return details, auto_count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enumerate Ghidra functions and naming coverage into JSON."
    )
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--program-name", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write JSON to this path instead of stdout.",
    )
    args = parser.parse_args()

    project_path = args.project_path.resolve()
    project_name = args.project_name or default_project_name(project_path)

    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface  # ty:ignore[unresolved-import]

    project = open_project_read_only(project_path, project_name)

    with pyghidra.program_context(project, "/" + args.program_name) as program:
        function_manager = program.getFunctionManager()
        decomp = DecompInterface()
        decomp.openProgram(program)

        functions: list[dict[str, Any]] = []
        total_auto_function_names = 0
        total_auto_params = 0
        total_auto_locals = 0
        decompile_failures = 0

        try:
            for function in function_manager.getFunctions(True):
                address = function.getEntryPoint().getOffset()
                function_name = function.getName()
                auto_function_name = looks_auto_name(function_name)
                if auto_function_name:
                    total_auto_function_names += 1

                entry: dict[str, Any] = {
                    "address": hex(address),
                    "name": function_name,
                    "signature": str(function.getSignature()),
                    "auto_function_name": auto_function_name,
                    "parameter_count": int(function.getParameterCount()),
                    "body_num_addresses": int(function.getBody().getNumAddresses()),
                }

                result = decomp.decompileFunction(function, 60, pyghidra.task_monitor())
                if not result.decompileCompleted():
                    entry["decompile_error"] = result.getErrorMessage()
                    entry["auto_param_count"] = 0
                    entry["auto_local_count"] = 0
                    entry["parameters"] = []
                    entry["locals"] = []
                    decompile_failures += 1
                    functions.append(entry)
                    continue

                high_function = result.getHighFunction()
                symbol_map = high_function.getLocalSymbolMap()
                param_symbols = [
                    symbol_map.getParamSymbol(i)
                    for i in range(symbol_map.getNumParams())
                    if symbol_map.getParamSymbol(i) is not None
                ]
                local_symbols = [
                    symbol
                    for symbol in symbol_map.getSymbols()
                    if not symbol.isParameter()
                ]

                parameters, auto_param_count = collect_symbol_details(param_symbols)
                locals_, auto_local_count = collect_symbol_details(local_symbols)
                total_auto_params += auto_param_count
                total_auto_locals += auto_local_count

                entry["auto_param_count"] = auto_param_count
                entry["auto_local_count"] = auto_local_count
                entry["parameters"] = parameters
                entry["locals"] = locals_
                functions.append(entry)
        finally:
            decomp.dispose()

    payload = {
        "project_path": str(project_path),
        "project_name": project_name,
        "program_name": args.program_name,
        "summary": {
            "function_count": len(functions),
            "auto_function_name_count": total_auto_function_names,
            "auto_parameter_name_count": total_auto_params,
            "auto_local_name_count": total_auto_locals,
            "decompile_failure_count": decompile_failures,
        },
        "functions": functions,
    }

    rendered = json.dumps(payload, indent=2)
    if args.output is None:
        print(rendered)
    else:
        args.output.write_text(rendered + "\n")
        print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
