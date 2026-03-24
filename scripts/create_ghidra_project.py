from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pyghidra

ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a Ghidra project and import an executable using PyGhidra."
    )
    parser.add_argument("binary", type=Path, help="Path to the binary executable.")
    parser.add_argument(
        "--project-path",
        type=Path,
        default=None,
        help=(
            "Directory in which to create the Ghidra project. "
            "Defaults to analysis-<first10ofsha256> in the current directory."
        ),
    )
    parser.add_argument(
        "--project-name",
        type=str,
        default=None,
        help=(
            "Name of the Ghidra project. "
            "Defaults to the first 10 characters of the binary's SHA-256 hex digest."
        ),
    )
    args = parser.parse_args()

    binary_path = args.binary.resolve()
    sha256 = sha256_file(binary_path)
    sha256_prefix = sha256[:10]

    project_name = args.project_name or sha256_prefix
    project_path = (
        args.project_path or Path.cwd() / f"analysis-{sha256_prefix}"
    ).resolve()
    project_path.mkdir(parents=True, exist_ok=True)

    print(f"Binary:       {binary_path}")
    print(f"SHA-256:      {sha256}")
    print(f"Project path: {project_path}")
    print(f"Project name: {project_name}")

    pyghidra.start()

    from ghidra.app.util.importer import AutoImporter, MessageLog
    from java.io import File
    from java.lang import Object

    project = pyghidra.open_project(str(project_path), project_name, create=True)
    monitor = pyghidra.task_monitor()
    log = MessageLog()
    consumer = Object()

    # importByUsingBestGuess returns LoadResults<Program> (Ghidra 11.x),
    # where each element is a Loaded<Program> wrapper — not a Program directly.
    load_results = AutoImporter.importByUsingBestGuess(
        File(str(binary_path)), project, "/", consumer, log, monitor
    )

    log_text = log.toString()
    if log_text:
        print(log_text)

    if not load_results:
        print("ERROR: AutoImporter returned no programs.")
        return 1

    # Persist all imported programs into the project before analysis.
    load_results.save(monitor)

    imported = []
    try:
        for loaded in load_results:
            program = loaded.getDomainObject()
            program_name = program.getName()
            print(f"Imported: {program_name} — running analysis...")
            pyghidra.analyze(program)
            program.getDomainFile().save(monitor)
            imported.append(program_name)
    finally:
        load_results.release(consumer)

    print(
        json.dumps(
            {
                "project_path": str(project_path),
                "project_name": project_name,
                "binary_sha256": sha256,
                "programs": imported,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
