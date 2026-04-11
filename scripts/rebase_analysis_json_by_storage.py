from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise SystemExit(f"ERROR: {path} is not a JSON object")
    return payload


def local_storage_map(bundle_function: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for local in bundle_function.get("locals", []):
        if not isinstance(local, dict):
            continue
        storage = local.get("storage")
        if isinstance(storage, str):
            result[storage] = local
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rebase a stale analysis artifact onto the current Ghidra state by "
            "matching locals through storage slots in old/current bundle exports."
        )
    )
    parser.add_argument("--old-bundle", type=Path, required=True)
    parser.add_argument("--current-bundle", type=Path, required=True)
    parser.add_argument("--analysis-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    old_bundle = load_json(args.old_bundle.resolve())
    current_bundle = load_json(args.current_bundle.resolve())
    artifact = load_json(args.analysis_json.resolve())

    old_functions = {
        function["address"]: function
        for function in old_bundle.get("functions", [])
        if isinstance(function, dict) and isinstance(function.get("address"), str)
    }
    current_functions = {
        function["address"]: function
        for function in current_bundle.get("functions", [])
        if isinstance(function, dict) and isinstance(function.get("address"), str)
    }

    rebased_functions: list[dict[str, Any]] = []
    for function in artifact.get("functions", []):
        if not isinstance(function, dict):
            continue
        address = function.get("address")
        if not isinstance(address, str):
            continue

        old_bundle_function = old_functions.get(address)
        current_bundle_function = current_functions.get(address)
        if old_bundle_function is None or current_bundle_function is None:
            rebased_functions.append(function)
            continue

        old_locals_by_name = {
            local.get("name"): local
            for local in old_bundle_function.get("locals", [])
            if isinstance(local, dict) and isinstance(local.get("name"), str)
        }
        current_locals_by_storage = local_storage_map(current_bundle_function)

        rebased = dict(function)
        new_locals: list[dict[str, Any]] = []
        for local in function.get("locals", []):
            if not isinstance(local, dict):
                continue
            current_name = local.get("current_name")
            if not isinstance(current_name, str):
                new_locals.append(local)
                continue
            old_local = old_locals_by_name.get(current_name)
            if old_local is None:
                new_locals.append(local)
                continue
            storage = old_local.get("storage")
            if not isinstance(storage, str):
                new_locals.append(local)
                continue
            current_local = current_locals_by_storage.get(storage)
            if current_local is None:
                new_locals.append(local)
                continue
            updated = dict(local)
            updated["current_name"] = current_local.get("name", current_name)
            new_locals.append(updated)

        rebased["locals"] = new_locals
        rebased_functions.append(rebased)

    output = {
        "program_name": artifact.get("program_name"),
        "functions": rebased_functions,
        "data_types": artifact.get("data_types", []),
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
