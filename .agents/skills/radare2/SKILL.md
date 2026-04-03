---
name: radare2
description: Use when Codex needs to inspect, triage, reverse engineer, or debug compiled binaries with radare2 and rabin2, especially ELF, PE, Mach-O, firmware blobs, crackmes, or stripped executables. Covers quick metadata extraction, strings/imports/sections review, staged code analysis, function inspection, xrefs, searching, visual mode, and basic debugger workflows.
---

# Radare2

## Overview

Use radare2 for staged binary analysis instead of jumping straight to maximal auto-analysis. Start with fast metadata extraction and lightweight analysis, then deepen only where the target or question requires it. In this repository, radare2 is a support tool for recovering enough meaning to name functions and variables accurately in Ghidra.

## Workflow

1. Triage the binary outside the main UI first.
2. Open it in radare2 with a minimal analysis pass.
3. Identify entrypoints, `main`, imports, strings, and candidate functions.
4. Inspect specific functions, basic blocks, and xrefs to recover semantics that improve naming.
5. Escalate to deeper analysis or debugger mode only when static inspection stops answering the naming question.

## Quick Start

Use this sequence for most binaries:

```sh
rabin2 -I -S -i -z ./binary
r2 -A ./binary
```

Inside r2, start with:

```text
afl
izz
s main
pdf
axt
```

If `main` is missing, inspect `entry0`, imports, exported symbols, and strings first, then step through likely dispatcher functions.

## Analysis Rules

- Prefer `rabin2` for fast triage before opening the interactive session.
- Prefer `aa` or `-A` first. Use `aaa` or deeper passes only when the lightweight pass misses functions or references.
- Prefer targeted inspection with `s`, `pdf`, `afb`, `axt`, and `axf` over whole-program brute force.
- Use `-w` only when the task explicitly requires patching bytes or instructions.
- Use `-d` only when static analysis is insufficient or runtime state matters.
- To avoid context pollution, route stderr to `/dev/null` when running a command unless the command failed, in which case rerun without the redirection.

## Common Workflows

### Static Triage

- Run `rabin2` commands from [references/triage.md](./references/triage.md).
- Open the binary with `r2 -A`.
- List functions with `afl`, inspect candidate ones with `pdf @ <name>`.
- Review strings with `izz` or `/ string`.
- Follow data/code references with `axt` and `axf`.

### Stripped Binary

- Start at `entry0`.
- Run `aa`, then `afl`.
- Use imports, strings, and xrefs to recover likely high-value code paths.
- Escalate to [references/static-analysis.md](./references/static-analysis.md) for `af`, `aar`, `aac`, `aab`, and manual function shaping.

### Runtime Inspection

- Reopen with `r2 -d ./binary` or `ood`.
- Set breakpoints at `main`, suspicious imports, or branch sites.

### Searching and Navigation

- Use `s`, `s+`, `s-`, `sf`, `s entry0`, and expression-based seeks to move quickly.
- Use `/`, `/i`, `/w`, and `/x` for text, case-insensitive, wide-string, and byte-pattern searches.
- Use visual mode (`V`, `V!`) when graph or panel navigation is faster than the prompt.
- See [references/navigation-and-search.md](./references/navigation-and-search.md).

## Reference Map

- Read [references/triage.md](./references/triage.md) for the fastest first-pass commands.
- Read [references/static-analysis.md](./references/static-analysis.md) when you need `aa`/`aaa`, function analysis, xrefs, or manual block recovery.
- Read [references/navigation-and-search.md](./references/navigation-and-search.md) for seek expressions, string/hex searches, and visual mode.

## Output Expectations

When using this skill, report findings in reverse-engineering terms:

- Binary format, architecture, and entrypoints.
- Proposed names or naming evidence for functions and variables.
- Important strings, imports, and xrefs that justify those names.
- Control-flow observations relevant to the naming problem.
- Concrete radare2 commands that reproduce the result.
