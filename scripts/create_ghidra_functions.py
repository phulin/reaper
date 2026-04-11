"""Create functions at specific addresses in a Ghidra project.

Disassembles bytes and creates function entries at the given flat addresses.
Useful for recovering code in regions Ghidra's auto-analysis missed.
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Disassemble and create functions at specified addresses."
    )
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--program-name", default=None)
    parser.add_argument(
        "--addresses",
        required=True,
        help="Comma-separated flat hex addresses (e.g. 0x11880c2b,0x11880d4b)",
    )
    args = parser.parse_args()

    addresses = [int(a.strip(), 0) for a in args.addresses.split(",")]
    project_path = args.project_path.resolve()
    project_name = args.project_name or default_project_name(project_path)

    pyghidra.start()

    from ghidra.app.cmd.disassemble import DisassembleCommand  # ty:ignore[unresolved-import]
    from ghidra.app.cmd.function import CreateFunctionCmd  # ty:ignore[unresolved-import]
    from java.lang import Object  # ty:ignore[unresolved-import]

    domain_file = None
    proj = pyghidra.open_project(str(project_path), project_name)
    root = proj.getProjectData().getRootFolder()
    for f in root.getFiles():
        if args.program_name is None or f.getName() == args.program_name:
            domain_file = f
            break

    if domain_file is None:
        raise SystemExit("ERROR: program not found")

    consumer = Object()
    program = domain_file.getDomainObject(
        consumer, True, False, pyghidra.task_monitor()
    )

    created = 0
    skipped = 0
    try:
        with pyghidra.transaction(program, "create_functions_at_addresses"):
            address_space = program.getAddressFactory().getDefaultAddressSpace()
            listing = program.getListing()
            fm = program.getFunctionManager()

            for flat_addr in addresses:
                addr = address_space.getAddress(flat_addr)

                # Check if function already exists
                existing = fm.getFunctionAt(addr)
                if existing is not None:
                    print(
                        f"  SKIP {hex(flat_addr)}: function already exists ({existing.getName()})"
                    )
                    skipped += 1
                    continue

                # Disassemble if needed
                instr = listing.getInstructionAt(addr)
                if instr is None:
                    cmd = DisassembleCommand(addr, None, True)
                    cmd.applyTo(program, pyghidra.task_monitor())
                    instr = listing.getInstructionAt(addr)
                    if instr is None:
                        print(f"  FAIL {hex(flat_addr)}: could not disassemble")
                        continue

                # Create function
                cmd = CreateFunctionCmd(addr)
                success = cmd.applyTo(program, pyghidra.task_monitor())
                if success:
                    fn = fm.getFunctionAt(addr)
                    print(
                        f"  OK   {hex(flat_addr)}: created {fn.getName()} ({fn.getBody().getNumAddresses()} bytes)"
                    )
                    created += 1
                else:
                    print(f"  FAIL {hex(flat_addr)}: CreateFunctionCmd failed")

        program.getDomainFile().save(pyghidra.task_monitor())
    finally:
        program.release(consumer)

    print(f"\nCreated {created} functions, skipped {skipped} existing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
