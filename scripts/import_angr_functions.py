from __future__ import annotations

import argparse
import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Iterable

import angr
from sqlalchemy import select

from reaper.db.models import CallGraphEdge, Function, Target
from reaper.db.session import create_session_factory


ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_slug(binary_path: Path, digest: str) -> str:
    if binary_path.name.startswith(digest):
        return digest
    return f"{binary_path.stem}-{digest[:12]}"


def iter_real_functions(cfg: angr.analyses.cfg.cfg_fast.CFGFast) -> Iterable:
    for function in cfg.kb.functions.values():
        if function.is_plt:
            continue
        yield function


def ensure_target(session, binary_path: Path, digest: str, metadata: dict) -> Target:
    target = session.execute(
        select(Target).where(Target.binary_sha256 == digest)
    ).scalar_one_or_none()
    if target is None:
        slug = make_slug(binary_path, digest)
        target = session.execute(
            select(Target).where(Target.slug == slug)
        ).scalar_one_or_none()

    if target is None:
        target = Target(slug=make_slug(binary_path, digest))
        session.add(target)

    existing_metadata = target.metadata_json or {}
    existing_metadata.update(metadata)
    target.display_name = binary_path.name
    target.binary_path = str(binary_path)
    target.binary_sha256 = digest
    target.metadata_json = existing_metadata
    session.flush()
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()

    binary_path = args.binary.resolve()
    digest = sha256_file(binary_path)

    project = angr.Project(str(binary_path), auto_load_libs=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        cross_references=True,
    )

    functions = list(iter_real_functions(cfg))
    metadata = {
        "binary_name": binary_path.name,
        "importer": "scripts/import_angr_functions.py",
        "loader": {
            "entry": project.entry,
            "min_addr": project.loader.min_addr,
            "max_addr": project.loader.max_addr,
            "arch": project.arch.name,
            "bits": project.arch.bits,
            "endness": project.arch.memory_endness,
        },
        "analysis": {
            "function_count": len(functions),
            "cfg_model": type(cfg).__name__,
        },
    }

    Session = create_session_factory()
    with Session() as session:
        target = ensure_target(session, binary_path, digest, metadata)

        existing_functions = {
            row.address: row
            for row in session.execute(
                select(Function).where(Function.target_id == target.id)
            ).scalars()
        }

        for function in functions:
            row = existing_functions.get(function.addr)
            if row is None:
                row = Function(target_id=target.id, address=function.addr)
                session.add(row)
                existing_functions[function.addr] = row

            name = function.name
            block_count = len(list(function.blocks))
            row.original_symbol_name = (
                name if name and not name.startswith("sub_") else None
            )
            row.proposed_name = (
                name if name and not name.startswith("sub_") else row.proposed_name
            )
            row.calling_convention = getattr(function.calling_convention, "name", None)
            row.ai_generated_summary = (
                f"Auto-imported from angr CFGFast. Blocks={block_count}, "
                f"size={function.size}, returning={function.returning}."
            )
            setattr(row, "complexity_score", Decimal(str(block_count)))

        session.flush()

        function_ids = {
            row.address: row.id
            for row in session.execute(
                select(Function).where(Function.target_id == target.id)
            ).scalars()
        }

        existing_edges = {
            (
                row.caller_function_id,
                row.callee_function_id,
                row.call_site_address,
            )
            for row in session.execute(
                select(CallGraphEdge).where(CallGraphEdge.target_id == target.id)
            ).scalars()
        }

        for function in functions:
            caller_id = function_ids.get(function.addr)
            if caller_id is None:
                continue

            for _, callee_addr, data in cfg.functions.callgraph.out_edges(
                function.addr, data=True
            ):
                callee_id = function_ids.get(callee_addr)
                if callee_id is None:
                    continue

                jumpkind = None
                ins_addr = None
                if isinstance(data, dict):
                    jumpkind = data.get("jumpkind")
                    ins_addr = data.get("ins_addr")
                if jumpkind and "Call" not in jumpkind:
                    continue

                key = (caller_id, callee_id, ins_addr)
                if key in existing_edges:
                    continue
                session.add(
                    CallGraphEdge(
                        target_id=target.id,
                        caller_function_id=caller_id,
                        callee_function_id=callee_id,
                        call_site_address=ins_addr,
                    )
                )
                existing_edges.add(key)

        session.commit()

        print(
            json.dumps(
                {
                    "target_id": target.id,
                    "target_slug": target.slug,
                    "binary_sha256": digest,
                    "functions": len(functions),
                    "edges": len(existing_edges),
                },
                indent=2,
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
