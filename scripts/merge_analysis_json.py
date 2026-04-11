from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_artifact(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise SystemExit(f"ERROR: {path} does not contain a JSON object")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Merge multiple analysis JSON artifacts into one reviewed bundle."
    )
    parser.add_argument(
        "--input", dest="inputs", action="append", type=Path, required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--program-name", default=None)
    args = parser.parse_args()

    merged_functions: dict[str, dict[str, Any]] = {}
    merged_types: dict[tuple[str, str], dict[str, Any]] = {}
    chosen_program_name = args.program_name

    for path in args.inputs:
        payload = load_artifact(path.resolve())
        if chosen_program_name is None and isinstance(payload.get("program_name"), str):
            chosen_program_name = payload["program_name"]

        for function in payload.get("functions", []):
            if not isinstance(function, dict):
                continue
            address = function.get("address")
            if not isinstance(address, str):
                continue
            merged_functions[address] = function

        for data_type in payload.get("data_types", []):
            if not isinstance(data_type, dict):
                continue
            name = data_type.get("name")
            path_key = data_type.get("path", "/reaper")
            if not isinstance(name, str):
                continue
            merged_types[(str(path_key), name)] = data_type

    output = {
        "program_name": chosen_program_name,
        "functions": [
            merged_functions[address]
            for address in sorted(merged_functions, key=lambda value: int(value, 0))
        ],
        "data_types": [
            merged_types[key]
            for key in sorted(merged_types, key=lambda item: (item[0], item[1]))
        ],
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
