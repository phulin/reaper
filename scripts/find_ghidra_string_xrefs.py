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


def collect_defined_strings(program: Any, pattern: str) -> list[dict[str, Any]]:
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    refs = program.getReferenceManager()
    pattern_lower = pattern.lower()
    matches: list[dict[str, Any]] = []

    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        value = data.getValue()
        if not isinstance(value, str):
            continue
        if pattern_lower not in value.lower():
            continue

        string_addr = data.getAddress()
        xrefs: list[dict[str, Any]] = []
        ref_iter = refs.getReferencesTo(string_addr)
        while ref_iter.hasNext():
            ref = ref_iter.next()
            from_addr = ref.getFromAddress()
            function = function_manager.getFunctionContaining(from_addr)
            xrefs.append(
                {
                    "from_address": str(from_addr),
                    "reference_type": str(ref.getReferenceType()),
                    "function_address": (
                        str(function.getEntryPoint()) if function is not None else None
                    ),
                    "function_name": function.getName()
                    if function is not None
                    else None,
                }
            )

        matches.append(
            {
                "address": str(string_addr),
                "string": value,
                "xrefs": xrefs,
            }
        )

    matches.sort(key=lambda item: (item["string"].lower(), item["address"]))
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find defined string matches in a Ghidra program and list cross-references."
    )
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--program-name", required=True)
    parser.add_argument(
        "--pattern",
        action="append",
        dest="patterns",
        required=True,
        help="Case-insensitive substring to search for. May be repeated.",
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
        "patterns": [],
    }

    with pyghidra.program_context(project, "/" + args.program_name) as program:
        for pattern in args.patterns:
            payload["patterns"].append(
                {
                    "pattern": pattern,
                    "matches": collect_defined_strings(program, pattern),
                }
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
