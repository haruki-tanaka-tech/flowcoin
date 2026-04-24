# Contributing to FlowCoin

Patches, reviews, documentation edits, and translations are all
welcome. This document walks you through the contribution flow.

## Before you start

1. **Read the spec.** Start with [doc/protocol.md](doc/protocol.md)
   and [doc/architecture.md](doc/architecture.md) before touching
   consensus or network code.
2. **Run the tests.** `./build/flowcoin_tests` — 55 assert-based
   groups. Keep them green before and after your change.
3. **Check the issue tracker.** Something you'd like to work on may
   already be in progress, or decided against for reasons you'd want
   to know.

## Development setup

```bash
git clone https://github.com/KristianPilatovich/flowcoin.git
cd flowcoin
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
./build/flowcoin_tests
```

Required toolchain: GCC 10+ / Clang 12+, CMake 3.20+, pthread. All
crypto / DB / networking libs are vendored under `src/` — nothing
to install.

## What makes a good pull request

- **One change per PR.** Refactors and features live in separate
  pull requests, even when they touch the same file.
- **A rationale in the commit message.** Not "what" — that's in the
  diff. "Why" — the constraint or bug that required this change.
- **Tests for new behavior.** If it's reachable from the network or
  from the RPC, it needs a test.
- **No cosmetic changes mixed with semantic ones.** Reformat a file
  in its own commit.
- **Consensus-breaking changes go through discussion first.** Open an
  issue tagged `consensus` before writing a line of code. We'd rather
  talk the change through than discard it during review.

## Coding style

- C++20, four-space indent, braces on the same line for functions.
- `snake_case` for free functions, types, and variables.
- `kPascalCase` for constants that are not already `constexpr` macros.
- Include guards: `#ifndef FLOWCOIN_MODULE_FILE_H` / `#define …` /
  `#endif`. `#pragma once` is fine for new files.
- Lines ≤ 100 chars; wrap sensibly.
- No exceptions in consensus code. Errors are return values.

## Vendored code

Don't edit the following — updates come from upstream only:

- `src/sqlite/`
- `src/zstd/`
- `src/libuv/`
- `src/xkcp/` and `src/hash/Keccak*`, `src/hash/SnP*`
- `src/crypto/ed25519*`, `src/crypto/curve25519*`
- `src/json/`

## Commit message format

```
one-line summary (<= 72 chars, imperative, no trailing period)

Paragraph explaining *why* the change is needed. Reference the
constraint or issue driving it. Do not describe the diff — the
reviewer can read it.

If the commit is user-visible, write a second paragraph describing
the effect from a user or operator perspective.
```

No "Signed-off-by" requirement. No AI-generated tags. Clean history.

## Reporting a security issue

Do NOT open a public issue. Email `pilatovichkristian2@gmail.com`
with the details. Expect a response within 72 hours. If the bug is
consensus-critical we will coordinate a patched release before
public disclosure.

## What counts as a "good first issue"

Labels in the tracker:

- `good first issue` — small, well-scoped, doesn't require deep
  context.
- `help wanted` — larger but self-contained. Author is happy to
  mentor.
- `docs` — documentation-only, no consensus implications.
- `consensus` — changes the validity rules. Discussion required
  before a PR.

## Questions

Open a GitHub Discussion under the
[Q&A category](https://github.com/KristianPilatovich/flowcoin/discussions),
or ask in the Telegram channel (`t.me/flowcoin_main`). Don't open
an issue for questions.
