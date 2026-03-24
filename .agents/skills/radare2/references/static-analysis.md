# Static Analysis

Use staged analysis. Deeper automation can be slow and can create false positives.

## Opening

```sh
r2 -A ./binary   # run a basic automatic analysis pass
r2 ./binary      # open without automatic analysis
r2 -w ./binary   # open for patching
```

## Core command set

```text
aa              analyze symbols and entrypoints
aaa             deeper analysis
afl             list functions
afi             show function info
s main          seek to main
s entry0        seek to entrypoint
pdf             print disassembly for current function
pdf @ main      print disassembly for a named function
afb             list basic blocks for current function
axt @ addr      xrefs to current address or target
axf @ addr      xrefs from current address or function
izz             list strings in the binary
ii              list imports inside r2
iI              binary info inside r2
iS              sections inside r2
```

## Function analysis

Use these when the default pass is insufficient:

```text
af              analyze current function
afr             analyze current function recursively
afn name        rename current function
afu addr        resize and analyze function until addr
af+ addr name   create a function manually
afb+ ...        add a basic block manually
```

## Program-wide refinement

```text
aab             basic-block analysis
aac             analyze function calls from current function
aaf             analyze all function calls
aar             analyze data references
aad             analyze pointer-to-pointer references
```

## Common inspection pattern

```text
afl
s main
pdf
axt
axf
```

If `main` is not obvious:

```text
s entry0
pdf
ii
izz
```

Follow imports and strings into nearby functions, then rename functions as their roles become clear.
