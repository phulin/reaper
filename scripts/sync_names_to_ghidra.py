"""Sync proposed_name values from the PostgreSQL database into a Ghidra project."""

from __future__ import annotations

import argparse
from pathlib import Path

import pyghidra
from sqlalchemy import select

from reaper.db.models import Function, Target
from reaper.db.session import create_session_factory


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply proposed function names from the DB into a Ghidra project."
    )
    parser.add_argument(
        "--binary-sha256",
        required=True,
        help="SHA-256 of the binary (used to locate the target in the DB).",
    )
    parser.add_argument(
        "--project-path",
        type=Path,
        required=True,
        help="Path to the Ghidra project directory.",
    )
    parser.add_argument(
        "--project-name",
        type=str,
        default=None,
        help="Ghidra project name (defaults to the project directory stem).",
    )
    args = parser.parse_args()

    project_path = args.project_path.resolve()
    # Directory is analysis-<prefix>; the .gpr file inside uses just <prefix>.
    dir_name = project_path.name
    default_name = (
        dir_name[len("analysis-") :] if dir_name.startswith("analysis-") else dir_name
    )
    project_name = args.project_name or default_name

    # --- Load names from Postgres ---
    Session = create_session_factory()
    with Session() as session:
        target = session.execute(
            select(Target).where(Target.binary_sha256 == args.binary_sha256)
        ).scalar_one_or_none()
        if target is None:
            print(f"ERROR: no target found for sha256={args.binary_sha256}")
            return 1

        functions = (
            session.execute(
                select(Function).where(
                    Function.target_id == target.id,
                    Function.proposed_name.is_not(None),
                )
            )
            .scalars()
            .all()
        )

    # address -> name
    name_map: dict[int, str] = {f.address: f.proposed_name for f in functions}
    print(f"Loaded {len(name_map)} named functions from DB (target '{target.slug}').")

    # --- Apply into Ghidra ---
    pyghidra.start()

    from ghidra.program.model.symbol import SourceType

    project = pyghidra.open_project(str(project_path), project_name)

    # Find the program in the project root
    root_folder = project.getProjectData().getRootFolder()
    files = list(root_folder.getFiles())
    if not files:
        print("ERROR: no programs found in the Ghidra project.")
        return 1
    if len(files) > 1:
        print(
            f"WARNING: {len(files)} programs in project; using '{files[0].getName()}'."
        )

    domain_file = files[0]
    from java.lang import Object

    consumer = Object()
    program = domain_file.getDomainObject(consumer, True, False, None)

    renamed = 0
    skipped = 0
    try:
        tx = program.startTransaction("sync_names_from_db")
        try:
            func_manager = program.getFunctionManager()
            for func in func_manager.getFunctions(True):
                addr = func.getEntryPoint().getOffset()
                name = name_map.get(addr)
                if name is None:
                    continue
                if func.getName() == name:
                    skipped += 1
                    continue
                func.setName(name, SourceType.USER_DEFINED)
                renamed += 1
        finally:
            program.endTransaction(tx, True)
        program.getDomainFile().save(None)
    finally:
        program.release(consumer)

    print(f"Renamed {renamed} functions, {skipped} already had the correct name.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
