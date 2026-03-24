from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pyghidra


@dataclass(slots=True)
class MergeGroupCandidate:
    symbol_name: str
    representative: str
    storage: str
    pc_address: str | None
    high_symbol: Any
    high_variable: Any
    merge_groups: dict[int, list[Any]]


def default_project_name(project_path: Path) -> str:
    dir_name = project_path.name
    if dir_name.startswith("analysis-"):
        return dir_name[len("analysis-") :]
    return dir_name


def open_program(project_path: Path, project_name: str, program_name: str | None):
    project = pyghidra.open_project(str(project_path), project_name)
    root = project.getProjectData().getRootFolder()
    files = list(root.getFiles())
    if not files:
        raise SystemExit("ERROR: no programs found in the Ghidra project root")
    if program_name is None:
        if len(files) > 1:
            names = ", ".join(file.getName() for file in files)
            raise SystemExit(
                f"ERROR: multiple programs in project root; specify --program-name ({names})"
            )
        return files[0]

    for domain_file in files:
        if domain_file.getName() == program_name:
            return domain_file
    names = ", ".join(file.getName() for file in files)
    raise SystemExit(
        f"ERROR: program '{program_name}' not found in project root; available: {names}"
    )


def collect_candidates(high_function) -> list[MergeGroupCandidate]:
    candidates: list[MergeGroupCandidate] = []
    seen: set[tuple[str, str]] = set()
    symbol_map = high_function.getLocalSymbolMap()
    for sym in symbol_map.getSymbols():
        high_var = sym.getHighVariable()
        if high_var is None:
            continue

        representative = str(high_var.getRepresentative())
        key = (sym.getName(), representative)
        if key in seen:
            continue
        seen.add(key)

        groups: dict[int, list[Any]] = defaultdict(list)
        for varnode in high_var.getInstances():
            groups[int(varnode.getMergeGroup())].append(varnode)

        if len(groups) < 2:
            continue

        pc_addr = None
        if high_var.getPCAddress() is not None:
            pc_addr = str(high_var.getPCAddress())

        candidates.append(
            MergeGroupCandidate(
                symbol_name=sym.getName(),
                representative=representative,
                storage=str(sym.getStorage()),
                pc_address=pc_addr,
                high_symbol=sym,
                high_variable=high_var,
                merge_groups=dict(sorted(groups.items())),
            )
        )
    return candidates


def find_candidate(
    candidates: list[MergeGroupCandidate],
    symbol_name: str | None,
    representative: str | None,
    storage: str | None,
    pc_address: str | None,
) -> MergeGroupCandidate:
    matches = candidates
    if symbol_name is not None:
        matches = [
            candidate for candidate in matches if candidate.symbol_name == symbol_name
        ]
    if representative is not None:
        matches = [
            candidate
            for candidate in matches
            if candidate.representative == representative
        ]
    if storage is not None:
        matches = [candidate for candidate in matches if candidate.storage == storage]
    if pc_address is not None:
        matches = [
            candidate for candidate in matches if candidate.pc_address == pc_address
        ]

    if not matches:
        raise SystemExit("ERROR: no split candidate matched the provided filters")
    if len(matches) > 1:
        details = "\n".join(
            (
                f"  name={candidate.symbol_name} rep={candidate.representative} "
                f"storage={candidate.storage} pc={candidate.pc_address}"
            )
            for candidate in matches
        )
        raise SystemExit(f"ERROR: candidate selection is ambiguous:\n{details}")
    return matches[0]


def print_candidates(candidates: list[MergeGroupCandidate]) -> None:
    if not candidates:
        print("No multi-merge-group locals found.")
        return

    for candidate in candidates:
        print(
            "candidate",
            f"name={candidate.symbol_name}",
            f"rep={candidate.representative}",
            f"storage={candidate.storage}",
            f"pc={candidate.pc_address}",
        )
        for group_id, varnodes in candidate.merge_groups.items():
            print(
                " ",
                f"group={group_id}",
                f"count={len(varnodes)}",
                f"representative={varnodes[0]}",
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "List and split Ghidra decompiler merge groups for a local variable using "
            "HighFunction.splitOutMergeGroup()."
        )
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
        help="Ghidra project name. Defaults to the project directory stem.",
    )
    parser.add_argument(
        "--program-name",
        type=str,
        default=None,
        help="Program name in the project root. Required if the root contains multiple programs.",
    )
    parser.add_argument(
        "--function-addr",
        required=True,
        help="Function entry address, for example 0x80005c78.",
    )
    parser.add_argument(
        "--symbol-name",
        type=str,
        default=None,
        help="Optional local symbol name to split. Omit for storage-based selection or to list candidates.",
    )
    parser.add_argument(
        "--merge-group",
        type=int,
        default=None,
        help="Merge group id to split out. Required when performing a split.",
    )
    parser.add_argument(
        "--representative",
        type=str,
        default=None,
        help="Optional HighVariable representative string for disambiguation.",
    )
    parser.add_argument(
        "--storage",
        type=str,
        default=None,
        help="Optional symbol storage string for disambiguation.",
    )
    parser.add_argument(
        "--pc-address",
        type=str,
        default=None,
        help="Optional PC address for disambiguation.",
    )
    parser.add_argument(
        "--rename-original",
        type=str,
        default=None,
        help="Optional new name for the original HighVariable after the split.",
    )
    parser.add_argument(
        "--rename-split",
        type=str,
        default=None,
        help="Optional new name for the split-out HighVariable.",
    )
    args = parser.parse_args()

    if args.merge_group is not None and args.symbol_name is None and args.storage is None:
        raise SystemExit(
            "ERROR: provide --symbol-name or --storage when using --merge-group"
        )
    if args.merge_group is None and (args.symbol_name is not None or args.storage is not None):
        raise SystemExit(
            "ERROR: --merge-group is required when selecting a variable to split"
        )

    project_path = args.project_path.resolve()
    project_name = args.project_name or default_project_name(project_path)

    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor
    from java.lang import Object

    domain_file = open_program(project_path, project_name, args.program_name)
    consumer = Object()
    program = domain_file.getDomainObject(consumer, True, False, None)
    try:
        address_factory = program.getAddressFactory()
        function_manager = program.getFunctionManager()
        function = function_manager.getFunctionAt(
            address_factory.getAddress(args.function_addr)
        )
        if function is None:
            raise SystemExit(f"ERROR: no function at {args.function_addr}")

        iface = DecompInterface()
        iface.openProgram(program)
        result = iface.decompileFunction(function, 90, ConsoleTaskMonitor())
        if not result.decompileCompleted():
            raise SystemExit(f"ERROR: decompile failed: {result.getErrorMessage()}")

        high_function = result.getHighFunction()
        candidates = collect_candidates(high_function)
        if args.symbol_name is None and args.storage is None:
            print_candidates(candidates)
            iface.dispose()
            return 0

        candidate = find_candidate(
            candidates,
            args.symbol_name,
            args.representative,
            args.storage,
            args.pc_address,
        )
        group_instances = candidate.merge_groups.get(args.merge_group)
        if group_instances is None:
            available = ", ".join(str(group_id) for group_id in candidate.merge_groups)
            raise SystemExit(
                f"ERROR: merge group {args.merge_group} not present; available: {available}"
            )

        with pyghidra.transaction(program, "split_ghidra_variable"):
            split_varnode = group_instances[0]
            split_high = high_function.splitOutMergeGroup(
                candidate.high_variable, split_varnode
            )

            if args.rename_original is not None:
                HighFunctionDBUtil.updateDBVariable(
                    candidate.high_symbol,
                    args.rename_original,
                    candidate.high_variable.getDataType(),
                    SourceType.USER_DEFINED,
                )
            if args.rename_split is not None:
                split_symbol = split_high.getSymbol()
                if split_symbol is None:
                    raise SystemExit(
                        "ERROR: split succeeded but produced no HighSymbol for renaming"
                    )
                HighFunctionDBUtil.updateDBVariable(
                    split_symbol,
                    args.rename_split,
                    split_high.getDataType(),
                    SourceType.USER_DEFINED,
                )

        program.getDomainFile().save(None)
        iface.dispose()

        iface = DecompInterface()
        iface.openProgram(program)
        refreshed = iface.decompileFunction(function, 90, ConsoleTaskMonitor())
        refreshed_c = refreshed.getDecompiledFunction().getC()
        iface.dispose()

        print("Split succeeded.")
        print(
            "original",
            f"name={candidate.symbol_name}",
            f"rep={candidate.high_variable.getRepresentative()}",
        )
        print(
            "split",
            f"rep={split_high.getRepresentative()}",
        )
        if args.rename_original is not None:
            print("renamed original ->", args.rename_original)
        if args.rename_split is not None:
            print("renamed split ->", args.rename_split)
        if args.rename_original is not None:
            print(
                "original visible after refresh:",
                args.rename_original in refreshed_c,
            )
        if args.rename_split is not None:
            print(
                "split visible after refresh:",
                args.rename_split in refreshed_c,
            )
        return 0
    finally:
        program.release(consumer)


if __name__ == "__main__":
    raise SystemExit(main())
