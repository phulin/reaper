from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

import pyghidra
from sqlalchemy import select

from reaper.db.models import DataType, Function, Target
from reaper.db.session import create_session_factory


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply database-backed names, summaries, and recovered data types into a Ghidra project."
    )
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--project-path", type=Path, required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument(
        "--program-name",
        help="Optional program name within the Ghidra project to update.",
    )
    args = parser.parse_args()

    Session = create_session_factory()
    with Session() as session:
        target = session.execute(
            select(Target).where(Target.binary_sha256 == args.binary_sha256)
        ).scalar_one_or_none()
        if target is None:
            print(f"ERROR: no target found for sha256={args.binary_sha256}")
            return 1

        functions = (
            session.execute(select(Function).where(Function.target_id == target.id))
            .scalars()
            .all()
        )
        data_types = (
            session.execute(select(DataType).where(DataType.target_id == target.id))
            .scalars()
            .all()
        )

    name_map = {
        function.address: function.proposed_name
        for function in functions
        if function.proposed_name
    }
    comment_map = {
        function.address: function.ai_generated_summary
        for function in functions
        if function.ai_generated_summary
    }

    pyghidra.start()

    from ghidra.program.model.data import (
        CategoryPath,
        CharDataType,
        DataTypeConflictHandler,
        Pointer32DataType,
        StructureDataType,
        UnsignedIntegerDataType,
        VoidDataType,
    )
    from ghidra.program.model.listing import CommentType
    from ghidra.program.model.listing import Program
    from ghidra.program.model.symbol import SourceType

    builtin_types = {
        "uint32_t": UnsignedIntegerDataType.dataType,
        "void*": Pointer32DataType(VoidDataType.dataType),
        "HMODULE*": Pointer32DataType(VoidDataType.dataType),
        "callback": Pointer32DataType(VoidDataType.dataType),
        "IMAGE_NT_HEADERS32*": Pointer32DataType(VoidDataType.dataType),
        "export_name_record*": Pointer32DataType(VoidDataType.dataType),
        "char": CharDataType.dataType,
    }

    project = pyghidra.open_project(str(args.project_path.resolve()), args.project_name)
    root_folder = project.getProjectData().getRootFolder()
    files = list(root_folder.getFiles())
    if not files:
        print("ERROR: no programs found in the Ghidra project.")
        return 1

    domain_file = None
    if args.program_name:
        for candidate in files:
            if candidate.getName() == args.program_name:
                domain_file = candidate
                break
        if domain_file is None:
            available = ", ".join(sorted(file.getName() for file in files))
            print(
                "ERROR: program not found in project: "
                f"{args.program_name}. Available: {available}"
            )
            return 1
    else:
        domain_file = files[0]

    from java.lang import Object

    consumer = Object()
    program = cast(
        Program,
        domain_file.getDomainObject(consumer, True, False, pyghidra.task_monitor()),
    )

    renamed = 0
    commented = 0
    created_types = 0
    try:
        tx = program.startTransaction("apply_db_analysis")
        try:
            dtm = program.getDataTypeManager()
            for recovered in data_types:
                if recovered.kind != "struct":
                    continue
                definition = recovered.definition or {}
                fields = definition.get("fields", [])
                struct = StructureDataType(
                    CategoryPath("/reaper"),
                    recovered.name,
                    int(definition.get("size_bytes", 0)),
                )
                for field in fields:
                    field_type = builtin_types.get(field["type"])
                    if field_type is None:
                        field_type = Pointer32DataType(VoidDataType.dataType)
                    struct.replaceAtOffset(
                        int(field["offset"]),
                        field_type,
                        field_type.getLength(),
                        field["name"],
                        "",
                    )
                dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER)
                created_types += 1

            func_manager = program.getFunctionManager()
            for func in func_manager.getFunctions(True):
                addr = func.getEntryPoint().getOffset()
                name = name_map.get(addr)
                comment = comment_map.get(addr)
                if name and func.getName() != name:
                    func.setName(name, SourceType.USER_DEFINED)
                    renamed += 1
                if comment and func.getComment() != comment:
                    func.setComment(comment)
                    code_unit = program.getListing().getCodeUnitAt(func.getEntryPoint())
                    if code_unit is not None:
                        code_unit.setComment(CommentType.PLATE, comment)
                    commented += 1
        finally:
            program.endTransaction(tx, True)
        program.getDomainFile().save(pyghidra.task_monitor())
    finally:
        program.release(consumer)

    print(
        f"Renamed {renamed} functions, applied {commented} comments, and synced {created_types} data types."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
