# Navigation and Search

Use seek expressions and search commands aggressively. They are often faster than broad auto-analysis.

## Seeking

```text
s               print current offset
s 0x401000      seek to absolute address
s+ 0x40         seek forward
s- 0x40         seek backward
s $$+4          seek relative using an expression
sf main         seek to a function
sf.             seek to current function start
s entry0        seek to entrypoint
s-              undo seek
s+              redo seek
```

Registers can participate in expressions during debugging or emulation:

```text
s rsp+0x40
```

## Printing

```text
pd              disassemble current block
pdf             disassemble current function
px              hexdump current block
ps @ addr       print string at addr
```

## Search

```text
/ password      search ASCII text
/i password     case-insensitive text search
/w Hello        wide-string search
/x 7f454c46     hex pattern search
//              repeat last search
f- hit*         clear generated hit flags
```

Search results are stored as `hit*` flags and can be revisited with `ps @ hit0_0` or by seeking to each hit.

## Visual mode

```text
V               enter visual mode
V!              enter visual panels
q               leave visual mode
p / P           rotate panels
c               toggle cursor mode
Enter           follow jump or call target
```

Use visual mode when graph structure or panel navigation is more informative than raw command output.
