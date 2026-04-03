# reaper

reaper is a mostly-automated reverse engineering workspace designed to be driven by a coding agent. The core idea is to give an agent a durable prompt, a small set of specialized skills, and a Ghidra-centric workflow so it can iteratively analyze binaries, persist conclusions directly in the project, and improve the surrounding tooling as it goes.

The project is intentionally organized around agent execution rather than around a traditional CLI application. `PROMPT.md` provides the main operating loop for an autonomous analysis run, while the repo-local skills in `.agents/skills/` support focused tasks such as decompiler interaction and second-opinion analysis.

## How It Works

At a high level, an agent working in this repository is expected to:

- import the binary into Ghidra and recover an initial function list
- use automation first where possible, including project scripts and analysis helpers
- keep the live analysis state in Ghidra itself
- have subagents emit structured JSON artifacts instead of mutating the project directly
- synthesize those artifacts into reviewed names, comments, and types before applying them to Ghidra
- iterate until the low-level function analysis supports a high-confidence report

This makes the repository part reverse engineering toolkit and part agent harness, with Ghidra as the durable state for an analysis run.

## Agent-First Workflow

The intended entrypoint for real work is [PROMPT.md](/Users/phulin/Documents/Projects/reaper/PROMPT.md). It tells a coding agent how to run an end-to-end analysis, what artifacts to maintain, and how to use subagent JSON plus Ghidra together.

The included repo-local skills currently cover:

- `pyghidra-decompiler`: guidance for scripting decompilation-oriented work through PyGhidra
- `radare2`: a fallback and second-opinion workflow for binary inspection and debugging

The workflow is deliberately biased toward writing scripts and reusable helpers instead of doing repetitive manual analysis. If a step can be automated, the agent should automate it and feed the results back into the Ghidra project and the run's JSON artifacts.

## Repository Map

- [PROMPT.md](/Users/phulin/Documents/Projects/reaper/PROMPT.md): primary agent instructions for an autonomous reverse engineering run
- [CODEBASE.md](/Users/phulin/Documents/Projects/reaper/CODEBASE.md): top-level outline for progressive disclosure
- [src/reaper/README.md](/Users/phulin/Documents/Projects/reaper/src/reaper/README.md): main Python package overview
- [scripts/README.md](/Users/phulin/Documents/Projects/reaper/scripts/README.md): operational scripts for Ghidra and analysis helpers
- `analysis*/`: generated Ghidra project directories and related working artifacts
- `artifacts/`: synthesized and per-subagent JSON analysis artifacts
- `report.md`, `preliminary_conclusions.md`, `task.md`: analysis outputs maintained during a run

## Setup

```bash
uv sync
```

Most Python execution in this repository should go through `uv run ...`, including scripts and validation commands.

## Current Status

The repository already supports an agent-driven reverse engineering loop with:

- Ghidra project creation, decompilation, and synchronization helpers
- a JSON artifact handoff path for subagent analysis
- initial skill support for decompiler-centric work and `radare2`-based inspection
- progressive-disclosure documentation so agents can pull in only the context they need

## Next Steps

Near-term improvements are focused on making the agent loop more structured and reliable:

- add a structured-loop skill, for example a Ralph Wiggum-style execution loop, to make long-running analysis more disciplined
- keep refining `PROMPT.md` so the default agent behavior is more explicit, more repeatable, and easier to recover when runs stall
- expand automation around repetitive reverse engineering tasks so less effort is spent on manual bookkeeping
