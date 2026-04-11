"""Scan every instruction in a Ghidra program for operands with a given immediate value.

Useful when Ghidra's xref analysis fails to record references to a global accessed
via DS-relative absolute addressing. We don't trust Ghidra's reference manager here;
we walk every instruction and look at the raw operand objects ourselves.
"""

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


def parse_immediate(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--program-name", required=True)
    parser.add_argument(
        "--immediate",
        type=parse_immediate,
        action="append",
        required=True,
        help="Immediate value to look for (e.g. 0xbc5a). Can repeat.",
    )
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    project_path = args.project_path.resolve()
    project_name = args.project_name or default_project_name(project_path)
    targets = set(args.immediate)

    pyghidra.start()
    project = open_project_read_only(project_path, project_name)

    from ghidra.program.model.scalar import Scalar  # ty:ignore[unresolved-import]
    from ghidra.program.model.address import Address  # ty:ignore[unresolved-import]

    hits: list[dict[str, Any]] = []

    with pyghidra.program_context(project, "/" + args.program_name) as program:
        listing = program.getListing()
        fm = program.getFunctionManager()
        instr_iter = listing.getInstructions(True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            num_ops = instr.getNumOperands()
            for op_index in range(num_ops):
                op_objs = instr.getOpObjects(op_index)
                for obj in op_objs:
                    val = None
                    if isinstance(obj, Scalar):
                        val = obj.getUnsignedValue()
                    elif isinstance(obj, Address):
                        val = obj.getOffset()
                    if val is None:
                        continue
                    if val in targets:
                        from_addr = instr.getAddress()
                        func = fm.getFunctionContaining(from_addr)
                        hits.append(
                            {
                                "from_address": str(from_addr),
                                "mnemonic": instr.getMnemonicString(),
                                "instruction": str(instr),
                                "operand_index": op_index,
                                "matched_value": hex(val),
                                "function_address": str(func.getEntryPoint())
                                if func is not None
                                else None,
                                "function_name": func.getName()
                                if func is not None
                                else None,
                            }
                        )
                        break

    payload = {
        "project_path": str(project_path),
        "project_name": project_name,
        "program_name": args.program_name,
        "immediates": [hex(v) for v in sorted(targets)],
        "hits": hits,
    }
    text = json.dumps(payload, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(text)
        print(args.output)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
