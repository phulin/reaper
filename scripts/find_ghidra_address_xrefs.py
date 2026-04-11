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


def open_project_read_only(project_path: Path, project_name: str):
    from ghidra.framework.model import ProjectLocator  # ty:ignore[unresolved-import]
    from ghidra.pyghidra import PyGhidraProjectManager  # ty:ignore[unresolved-import]

    project_locator = ProjectLocator(str(project_path), project_name)
    project_manager = PyGhidraProjectManager()
    return project_manager.openProject(project_locator, True, False)


def parse_address(value: str) -> int:
    if ":" in value:
        segment_text, offset_text = value.split(":", 1)
        return (int(segment_text, 16) << 16) | int(offset_text, 16)
    return int(value, 0)


def collect_xrefs_for_address(program: Any, address_value: int) -> dict[str, Any]:
    address_factory = program.getAddressFactory()
    function_manager = program.getFunctionManager()
    listing = program.getListing()
    refs = program.getReferenceManager()

    addr = address_factory.getDefaultAddressSpace().getAddress(address_value)
    data = listing.getDefinedDataContaining(addr)
    symbol = program.getSymbolTable().getPrimarySymbol(addr)

    xrefs: list[dict[str, Any]] = []
    ref_iter = refs.getReferencesTo(addr)
    while ref_iter.hasNext():
        ref = ref_iter.next()
        from_addr = ref.getFromAddress()
        function = function_manager.getFunctionContaining(from_addr)
        xrefs.append(
            {
                "from_address": str(from_addr),
                "reference_type": str(ref.getReferenceType()),
                "function_address": str(function.getEntryPoint())
                if function is not None
                else None,
                "function_name": function.getName() if function is not None else None,
            }
        )

    payload: dict[str, Any] = {
        "address": str(addr),
        "symbol_name": symbol.getName() if symbol is not None else None,
        "data_type": str(data.getDataType()) if data is not None else None,
        "value_repr": repr(data.getValue()) if data is not None else None,
        "xrefs": xrefs,
    }
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List Ghidra cross-references to exact addresses."
    )
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--program-name", required=True)
    parser.add_argument(
        "--address",
        action="append",
        dest="addresses",
        required=True,
        help="Address to inspect, e.g. 0x1eb0005d or 1eb0:005d. May be repeated.",
    )
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    project_path = args.project_path.resolve()
    project_name = args.project_name or default_project_name(project_path)

    pyghidra.start()
    project = open_project_read_only(project_path, project_name)

    payload: dict[str, Any] = {
        "project_path": str(project_path),
        "project_name": project_name,
        "program_name": args.program_name,
        "addresses": [],
    }

    with pyghidra.program_context(project, "/" + args.program_name) as program:
        for raw_address in args.addresses:
            payload["addresses"].append(
                collect_xrefs_for_address(program, parse_address(raw_address))
            )

    text = json.dumps(payload, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(text)
        print(args.output)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
