"""Create missing Ghidra functions from likely 16-bit function prologues.

Scans decoded instructions for the following entry patterns:

- `mov ax,ss; nop; inc bp; push bp; mov bp,sp`
- `inc bp; push bp; mov bp,sp`

When both patterns overlap, the longer pattern wins so only the outer entry is
created. Existing functions are left untouched.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pyghidra


def default_project_name(project_path: Path) -> str:
    dir_name = project_path.name
    if dir_name.startswith("analysis-"):
        return dir_name[len("analysis-") :]
    return dir_name


def instruction_text(instr) -> str:
    return instr.toString().lower()


def find_candidates(program) -> list[tuple[int, str]]:
    listing = program.getListing()
    matches: list[tuple[int, str]] = []

    instructions = listing.getInstructions(True)
    all_instructions = []
    while instructions.hasNext():
        all_instructions.append(instructions.next())

    for index, instr in enumerate(all_instructions):
        start = instr.getAddress()
        text = instruction_text(instr)
        pattern = None

        if text == "mov ax,ss" and index + 4 < len(all_instructions):
            first = all_instructions[index + 1]
            second = all_instructions[index + 2]
            third = all_instructions[index + 3]
            fourth = all_instructions[index + 4]
            if (
                first.getAddress() == instr.getNext().getAddress()
                and second.getAddress() == first.getNext().getAddress()
                and third.getAddress() == second.getNext().getAddress()
                and fourth.getAddress() == third.getNext().getAddress()
                and instruction_text(first) == "nop"
                and instruction_text(second) == "inc bp"
                and instruction_text(third) == "push bp"
                and instruction_text(fourth) == "mov bp,sp"
            ):
                pattern = "long"
        elif text == "inc bp" and index + 2 < len(all_instructions):
            first = all_instructions[index + 1]
            second = all_instructions[index + 2]
            if (
                first.getAddress() == instr.getNext().getAddress()
                and second.getAddress() == first.getNext().getAddress()
                and instruction_text(first) == "push bp"
                and instruction_text(second) == "mov bp,sp"
            ):
                pattern = "short"

        if pattern is not None:
            matches.append((start.getOffset(), pattern))

    long_offsets = {offset for offset, pattern in matches if pattern == "long"}
    deduped: list[tuple[int, str]] = []
    for offset, pattern in matches:
        if pattern == "short" and (offset - 3) in long_offsets:
            continue
        deduped.append((offset, pattern))

    return deduped


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create missing functions from likely 16-bit prologue patterns."
    )
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--program-name", default="SIMTOWER.EX_")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report candidate entrypoints without modifying the project.",
    )
    args = parser.parse_args()

    project_path = args.project_path.resolve()
    project_name = args.project_name or default_project_name(project_path)

    pyghidra.start()

    from ghidra.app.cmd.function import CreateFunctionCmd  # ty:ignore[unresolved-import]
    from ghidra.program.model.listing import Function  # ty:ignore[unresolved-import]

    project = pyghidra.open_project(str(project_path), project_name)

    created = 0
    skipped = 0
    failed = 0

    with pyghidra.program_context(project, "/" + args.program_name) as program:
        fm = program.getFunctionManager()
        address_space = program.getAddressFactory().getDefaultAddressSpace()
        candidates = find_candidates(program)

        if args.dry_run:
            missing = []
            for offset, pattern in candidates:
                addr = address_space.getAddress(offset)
                if fm.getFunctionContaining(addr) is None:
                    missing.append((addr.toString(), pattern))
            print(f"candidate_count={len(candidates)} missing_count={len(missing)}")
            for addr_text, pattern in missing:
                print(f"{addr_text}\t{pattern}")
            return 0

        with pyghidra.transaction(program, "create missing functions from prologues"):
            for offset, pattern in candidates:
                addr = address_space.getAddress(offset)
                containing: Function | None = fm.getFunctionContaining(addr)
                if containing is not None:
                    skipped += 1
                    continue

                success = CreateFunctionCmd(addr).applyTo(
                    program, pyghidra.task_monitor()
                )
                if success:
                    created += 1
                    print(f"OK   {addr} ({pattern})")
                else:
                    failed += 1
                    print(f"FAIL {addr} ({pattern})")

        program.getDomainFile().save(pyghidra.task_monitor())

    print(
        f"Created {created} functions, skipped {skipped} existing candidates, failed {failed}."
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
