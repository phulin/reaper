from __future__ import annotations

import argparse
import json
from pathlib import Path

import pyghidra


def parse_address(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decompile selected functions from an existing Ghidra project."
    )
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--program-name", required=True)
    parser.add_argument(
        "--address",
        dest="addresses",
        action="append",
        type=parse_address,
        default=[],
        help="Function entry address to decompile. May be provided multiple times.",
    )
    parser.add_argument(
        "--include-signature",
        action="store_true",
        help="Include the recovered function signature in the output.",
    )
    args = parser.parse_args()

    pyghidra.start()

    project = pyghidra.open_project(
        str(args.project_path.resolve()),
        args.project_name,
    )

    from ghidra.app.decompiler import DecompInterface  # ty:ignore[unresolved-import]

    with pyghidra.program_context(project, "/" + args.program_name) as program:
        fm = program.getFunctionManager()
        decomp = DecompInterface()
        decomp.openProgram(program)

        try:
            for address in args.addresses:
                func = fm.getFunctionContaining(
                    program.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(address)
                )
                if func is None or func.getEntryPoint().getOffset() != address:
                    print(
                        json.dumps(
                            {"address": hex(address), "error": "function not found"},
                            indent=2,
                        )
                    )
                    continue

                result = decomp.decompileFunction(func, 60, pyghidra.task_monitor())
                payload = {
                    "address": hex(address),
                    "name": func.getName(),
                    "decompiled": result.getDecompiledFunction().getC()
                    if result.decompileCompleted()
                    else None,
                }
                if args.include_signature:
                    payload["signature"] = str(func.getSignature())
                print(json.dumps(payload, indent=2))
        finally:
            decomp.dispose()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
