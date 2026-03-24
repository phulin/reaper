# Triage

Use `rabin2` for the first pass because it is faster and cheaper than opening a full analysis session.

## Core commands

```sh
rabin2 -I ./binary      # file info, arch, bits, format
rabin2 -S ./binary      # sections
rabin2 -i ./binary      # imports
rabin2 -s ./binary      # symbols
rabin2 -E ./binary      # exports
rabin2 -M ./binary      # main symbol if present
rabin2 -e ./binary      # entrypoint
rabin2 -l ./binary      # linked libraries
rabin2 -z ./binary      # strings from data/string-bearing sections
```

## Use this pass to answer

- What format and architecture is this?
- Is the file stripped?
- Which imports or exports suggest crypto, networking, process injection, file I/O, or auth logic?
- Which strings or section names point to the logic the user cares about?

## Good next steps

- If imports or strings reveal the likely code path, open `r2 -A ./binary` and inspect those references first.
- If `main` exists, go there immediately with `s main` then `pdf`.
- If the file is stripped, start from `entry0`, imports, and strings.
