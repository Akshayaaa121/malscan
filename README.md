# malscan — a rules-based malware detection engine

## Build

```
make
```

Produces the `malscan` binary. `make debug` builds an ASan/UBSan-instrumented
`malscan_debug` for memory-safety testing.

## Usage

```
./malscan <file_to_scan> <rules_directory>
```

- `<file_to_scan>` — any file at all (binary, text, unicode, whatever). It is
  always treated as an opaque byte stream; no encoding or structure is assumed.
- `<rules_directory>` — a directory containing one rule file per malware
  family. It may contain arbitrarily nested subdirectories; every regular
  file found anywhere underneath is considered as a candidate rule file
  (files that don't parse as rule files are skipped with a warning, not
  treated as fatal errors — this lets you keep a stray `README.txt` in
  the rules tree without breaking the scan).

Exit codes: `0` = no malware matched, `1` = at least one family matched,
`2` = usage/IO error (bad args, unreadable target file).

## Rule file format

Each malware family gets its own dedicated file, split into exactly two
sections:

```
[metadata]
name = EvilTrojan
description = Generic remote-access trojan that injects into other processes

[rules]
"CreateRemoteThread" and "VirtualAllocEx"
{4D 5A 90 00 03 00 00 00} and "kernel32.dll" nocase
"powershell -enc" or "cmd.exe /c" or {68 74 74 70 3A 2F 2F}
not "SAFE_MARKER_1234" and "evil_payload_signature"
```

- **`[metadata]`** — `name` and `description` for the malware family.
- **`[rules]`** — the actual detection logic. **One rule per line.**
  The file matches the scanned target if *any* rule line evaluates true
  (rules within a file are effectively OR'd at the family level).

### Terms

A rule line is a boolean expression built from one or more **terms**:

| Syntax                    | Meaning                                              |
|---------------------------|-------------------------------------------------------|
| `"literal text"`           | exact byte sequence (case-sensitive)                  |
| `"literal text" nocase`    | same, but case-insensitive                            |
| `{4D 5A 90 ??}`            | raw hex byte pattern; `??` = wildcard byte             |

String literals support escapes: `\n` `\t` `\r` `\\` `\"` and `\xHH` for an
arbitrary raw byte (useful for embedding non-printable bytes in an otherwise
textual pattern).

### Boolean operators

Terms combine with `and`, `or`, and a prefix `not`. Precedence is the usual
one: `not` binds tightest, then `and`, then `or` — evaluated left to right.
**Parentheses are not supported** (documented simplification for this
open-ended problem); if you need more complex grouping, split the logic
across multiple rule lines (which are already OR'd together) or multiple
`and`-chains.

### Comments / blank lines

Lines starting with `#` and blank lines are ignored anywhere in the file.

## Matching engine

- The target file is read once, fully, as raw bytes — never through any
  text function that assumes NUL-termination or a particular encoding.
- Exact, case-sensitive patterns (the common case) use
  **Boyer-Moore-Horspool**, which skips ahead multiple bytes per
  comparison and performs well on large binaries.
- Patterns containing wildcards or the `nocase` modifier fall back to a
  direct scan (still fine in practice since such patterns are typically
  short signature fragments).
- Directory traversal is a straightforward recursive walk over `readdir()`
  that does **not** follow symlinks, to avoid infinite loops on cyclic
  symlink trees.

## Files in this project

```
malscan.c                          - the entire engine (single file)
Makefile
rules/trojans/evil_trojan.rule     - example rule file
rules/ransomware/subfamily/cryptolock.rule
                                    - example of nested-subfolder rule file
rules/README.txt                   - stray non-rule file (verifies it's skipped)
samples/malicious1.bin             - triggers EvilTrojan (hex header + nocase string)
samples/malicious2.bin             - triggers both families (AND/NOT logic + hex wildcard)
samples/clean.txt                  - benign file, should report zero matches
```

## Known simplifications (by design, given the open-ended brief)

- No parenthesized grouping within a single rule line (see above).
- A "rule file" is recognized heuristically by the presence of
  `[metadata]` and/or `[rules]` headers; arbitrary junk files in the
  rules tree are simply skipped rather than causing an error, since the
  brief allows arbitrary nesting and doesn't guarantee every file present
  is a rule file.
- Malformed individual rule *lines* are reported to stderr with the
  file name and line number and then skipped, so one bad line in an
  otherwise valid rule file doesn't take down the whole family's other
  (valid) rules.
