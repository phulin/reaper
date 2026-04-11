from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pyghidra


def default_project_name(project_path: Path) -> str:
    dir_name = project_path.name
    if dir_name.startswith("analysis-"):
        return dir_name[len("analysis-") :]
    return dir_name


def parse_address(value: str) -> int:
    return int(value, 0)


def open_project_read_only(project_path: Path, project_name: str):
    from ghidra.framework.model import ProjectLocator  # ty:ignore[unresolved-import]
    from ghidra.pyghidra import PyGhidraProjectManager  # ty:ignore[unresolved-import]

    project_locator = ProjectLocator(str(project_path), project_name)
    project_manager = PyGhidraProjectManager()
    return project_manager.openProject(project_locator, True, False)


def symbol_payload(symbol: Any) -> dict[str, Any]:
    return {
        "name": symbol.getName(),
        "data_type": str(symbol.getDataType()),
        "storage": str(symbol.getStorage()),
        "category_index": int(symbol.getCategoryIndex()),
        "is_parameter": bool(symbol.isParameter()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export decompiled Ghidra details for a selected function list."
    )
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--program-name", required=True)
    parser.add_argument(
        "--address",
        dest="addresses",
        action="append",
        type=parse_address,
        default=[],
        help="Function address to export. May be repeated.",
    )
    parser.add_argument(
        "--address-file",
        type=Path,
        default=None,
        help="Optional newline-delimited address list.",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    project_path = args.project_path.resolve()
    project_name = args.project_name or default_project_name(project_path)

    addresses = list(args.addresses)
    if args.address_file is not None:
        for line in args.address_file.read_text().splitlines():
            stripped = line.strip()
            if stripped:
                addresses.append(parse_address(stripped))

    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface  # ty:ignore[unresolved-import]

    project = open_project_read_only(project_path, project_name)

    payload: dict[str, Any] = {
        "project_path": str(project_path),
        "project_name": project_name,
        "program_name": args.program_name,
        "functions": [],
    }

    with pyghidra.program_context(project, "/" + args.program_name) as program:
        function_manager = program.getFunctionManager()
        address_space = program.getAddressFactory().getDefaultAddressSpace()
        decomp = DecompInterface()
        decomp.openProgram(program)

        try:
            for address in addresses:
                function = function_manager.getFunctionAt(
                    address_space.getAddress(address)
                )
                if function is None:
                    payload["functions"].append(
                        {"address": hex(address), "error": "function not found"}
                    )
                    continue

                result = decomp.decompileFunction(function, 90, pyghidra.task_monitor())
                function_payload: dict[str, Any] = {
                    "address": hex(address),
                    "name": function.getName(),
                    "signature": str(function.getSignature()),
                    "comment": function.getComment(),
                    "body_num_addresses": int(function.getBody().getNumAddresses()),
                }

                if not result.decompileCompleted():
                    function_payload["decompile_error"] = result.getErrorMessage()
                    payload["functions"].append(function_payload)
                    continue

                high_function = result.getHighFunction()
                symbol_map = high_function.getLocalSymbolMap()
                function_payload["decompiled"] = (
                    result.getDecompiledFunction().getC()
                    if result.getDecompiledFunction() is not None
                    else None
                )
                function_payload["parameters"] = [
                    symbol_payload(symbol_map.getParamSymbol(i))
                    for i in range(symbol_map.getNumParams())
                    if symbol_map.getParamSymbol(i) is not None
                ]
                function_payload["locals"] = [
                    symbol_payload(symbol)
                    for symbol in symbol_map.getSymbols()
                    if not symbol.isParameter()
                ]
                payload["functions"].append(function_payload)
        finally:
            decomp.dispose()

    args.output.write_text(json.dumps(payload, indent=2) + "\n")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
