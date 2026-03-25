# reaper

reaper is a mostly-automated reverse engineering workspace designed to be driven by a coding agent. The core idea is to give an agent a durable prompt, a small set of specialized skills, and a database-backed working memory so it can iteratively analyze binaries, persist conclusions, and improve the surrounding tooling as it goes.

The project is intentionally organized around agent execution rather than around a traditional CLI application. `PROMPT.md` provides the main operating loop for an autonomous analysis run, while the repo-local skills in `.agents/skills/` support focused tasks such as decompiler interaction and second-opinion analysis.

## How It Works

At a high level, an agent working in this repository is expected to:

- create or select a database record for the target being analyzed
- import the binary into Ghidra and recover an initial function list
- use automation first where possible, including project scripts and analysis helpers
- store findings in the database as the source of truth
- apply recovered names, comments, and types back into Ghidra
- iterate until the low-level function analysis supports a high-confidence report

This makes the repository part reverse engineering toolkit, part memory system, and part agent harness.

## Agent-First Workflow

The intended entrypoint for real work is [PROMPT.md](/Users/phulin/Documents/Projects/reaper/PROMPT.md). It tells a coding agent how to run an end-to-end analysis, what artifacts to maintain, and how to use the database and Ghidra together.

The included repo-local skills currently cover:

- `pyghidra-decompiler`: guidance for scripting decompilation-oriented work through PyGhidra
- `radare2`: a fallback and second-opinion workflow for binary inspection and debugging

The workflow is deliberately biased toward writing scripts and reusable helpers instead of doing repetitive manual analysis. If a step can be automated, the agent should automate it and feed the results back into the database and project state.

## Repository Map

- [PROMPT.md](/Users/phulin/Documents/Projects/reaper/PROMPT.md): primary agent instructions for an autonomous reverse engineering run
- [CODEBASE.md](/Users/phulin/Documents/Projects/reaper/CODEBASE.md): top-level outline for progressive disclosure
- [SCHEMA.md](/Users/phulin/Documents/Projects/reaper/SCHEMA.md): concise description of the analysis database schema
- [src/reaper/README.md](/Users/phulin/Documents/Projects/reaper/src/reaper/README.md): main Python package overview
- [scripts/README.md](/Users/phulin/Documents/Projects/reaper/scripts/README.md): operational scripts for migrations, Ghidra, and analysis helpers
- `analysis*/`: generated Ghidra project directories and related working artifacts
- `report.md`, `preliminary_conclusions.md`, `task.md`: analysis outputs maintained during a run

## Setup

```bash
uv sync
uv run python scripts/migrate.py upgrade head
```

Most Python execution in this repository should go through `uv run ...`, including scripts and validation commands.

## Current Status

The repository already supports an agent-driven reverse engineering loop with:

- a Postgres-backed schema for targets, functions, annotations, modules, call-graph edges, and recovered data types
- Ghidra project creation, decompilation, and synchronization helpers
- initial skill support for decompiler-centric work and `radare2`-based inspection
- progressive-disclosure documentation so agents can pull in only the context they need

## Next Steps

Near-term improvements are focused on making the agent loop more structured and reliable:

- add a structured-loop skill, for example a Ralph Wiggum-style execution loop, to make long-running analysis more disciplined
- keep refining `PROMPT.md` so the default agent behavior is more explicit, more repeatable, and easier to recover when runs stall
- expand automation around repetitive reverse engineering tasks so less effort is spent on manual bookkeeping
