# Impact selection

`make check-slow` runs for about half an hour. Most of that is CBMC
proofs and differential runs that a one-file change cannot break, so
waiting for all of it after every edit wastes the loop. `make impact`
prints the gates a change can break, and `make impact-run` runs them.

    make impact BASE=main        # print the plan
    make impact-run BASE=main    # run it
    make impact TIER=slow        # drop the lanes only the nightly runs

`BASE` is the revision to compare against, default `HEAD`. `git diff
BASE` compares it to the working tree, and the tool adds the untracked
files, so a dirty tree reports what it holds — which is what an inner
loop always is. `TIER` narrows the plan to the gates a tier already
runs: `check`, `slow` (what `check-slow` adds), or the default, which
keeps the cross-compilation and sanitizer lanes too.

The plan labels each command with that tier, so a selected run can be
compared against the tier it stands in for rather than against a
different set of gates.

## Selection is never a landing gate

Every change still passes `make check` before it is committed and
`make check-slow` before it is called done. CI runs `make ci`, and the
nightly runs everything. Nothing here changes that; CLAUDE.md states
those rules and they stay in force. A selected run answers "did the
thing I just edited break", not "is this ready to land".

## What the tool selects

For each changed path the plan carries:

- **Test binaries.** Every `bin/` target whose sources name the file,
  run through `make run-<name>`. When a `bin/` rule's prerequisite is
  another `bin/` rule, the plan reads that rule too: it is where the two
  example binaries name their sources. `bin/diff` and the two sequence
  enumerations run through the target that builds the Lean oracle first.
- **Scripts.** `test/e2e.sh` when a changed source is compiled into a
  binary it runs; the cross lanes when a changed source is in their
  roster.
- **Lanes that write their own compile lines.** Every gate target whose
  recipe names the file: the three differential arms, the Wycheproof
  suites, the sanitizer lane, the Cortex-M3 roster, `rand-check`, and
  the lints whose recipe holds its own file list.
- **Proofs.** Every CBMC harness whose launch line or includes name the
  file, as `make prove-one HARNESS=<name>`.
- **The differential.** Any change under `spec/` selects `make lint-spec`,
  all four differential arms and both sequence enumerations. So does any
  change `bin/diff` compiles: each arm compiles the same driver with one
  more define, and the Makefile names the rows that meet real C in one
  arm alone.
- **Packaged-object legs.** One leg per axis value `make check` builds —
  the default object, `TRUST=ca` and `TRUST=webpki`. A source selects
  every leg that packages it, so a file the default object filters out
  still selects the leg that compiles it, and so does an `#ifdef` body
  only one leg's defines keep.
- **Codegen gates.** A source in `CODEGEN_SRCS` selects the wide-multiply
  and runtime-symbol gates, which read what the compiler emits per file.
- **Violations.** Every `test/violations/*.violation` that edits the file.
- **Helper scripts.** A changed `.py` or `.sh` selects every make target
  whose recipe names it, which is the only statement of where it belongs.
- **Lints,** by what each one reads.

Two targets stop unless a variable says what to run: `make prove-one`
without `HARNESS` and `make cross-check` without `CROSS` each print what
to set and exit 1. The plan never emits either bare. It names the
harness, and it runs the cross lanes through the two docker scripts,
which pass `CROSS` and `RUNNER`. `make cxx-check` is the same shape for
`RAND`, which has no default: the plan names `RAND=extern`, as `make
check` does.

## What it over-selects on purpose

The rule is over-select, never miss. A plan that runs a gate it did not
have to costs minutes; a plan that drops a gate that would have failed
lets a bad commit land, which is worse than running everything. So:

- A changed path the mapping cannot place selects everything and says
  which path did it. That covers an edit to the Makefile, a root header,
  `tools/toolchain.env`, anything under `.github/` or `.semgrep/`,
  `proof/run.sh`, `proof/prove-one.sh`, and `.gitignore`, which decides
  which files the gates that read `git ls-files` see at all.
- A source no list in the tree names selects everything too, which is
  what a file this change adds looks like. `make -qp` holds every
  variable and every recipe, and the harnesses name the modules they
  include; a path in neither is a path no rule reads. The gates that
  judge it read git's own file list —
  `lint-trust-separation` requires each new root `webpki*.c` file to
  join `WEBPKI_SRCS`, and `lint-codegen-partition` requires every
  library source to be in exactly one gate list — and neither has a
  source list to narrow by.
- Any root header selects everything, because `$(HDRS)` is a
  prerequisite of every test binary. Narrowing `rsa.h` to the RSA
  binaries would be a guess the Makefile does not support.
- A variable inside a make function expands to its whole value:
  `$(filter-out p256.c,$(SRCS))` yields every name in `SRCS`, `p256.c`
  included. Reproducing `filter-out` would mean reimplementing make.
- Any change under `spec/` selects all four differential arms. The
  differential is one binary run, so there is nothing finer to select.

## What it saves, measured

Four changes, each a comment-only line, timed on one development
machine (Apple silicon, 10 cores, the host `cc`, which is Apple clang
21 there; the LLVM pin in `tools/toolchain.env` names the checkers and
the cross toolchain, not this compiler). The selected column is `make
impact-run TIER=slow`, so it holds the same universe of gates as `make
check-slow` and no cross-compilation lane. "Warm" means the proof cache
already held every verdict but the edited module's; "cold" means an
empty `proof/.cache`, which is what a first run after a clone costs.

| change | selected | check-slow, warm | check-slow, cold |
| --- | --- | --- | --- |
| `webpki_time.c` | 503 s | 676 s | 2361 s |
| `spec/Spec/WebpkiTime.lean` | 395 s | 688 s | 2361 s |
| `sha3.c` | 218 s | 692 s † | 2361 s † |
| `test/webpki_time_test.c` | 39 s | 692 s | 2361 s |

† reused, not measured for that row. The 692 s warm run was measured
for the test-only change and the 2361 s cold run once for all four:
`make check-slow` runs the same gates whatever changed, so its cost
does not depend on the row. Only the selected column is per row.

Read those honestly. Against a cold slow tier every case saves most of
the wall clock, but a developer rarely pays that: the proof cache is
keyed by content, so a warm repeat already skips the proofs a change
cannot break. Against the warm number, selection saves 26% for
`webpki_time.c`, 43% for the spec file, 68% for `sha3.c` and 94% for
the test-only change. Read as savings throughout, so the four numbers
compare. The first two are real and not dramatic: `webpki_time.c` is in
`$(SRCS)`, so it links into `bin/unit`, `bin/diff`, the e2e clients and
the sequence enumeration, and those gates are most of what check-slow
costs. `sha3.c` is outside `$(SRCS)` until `KEX=pq` packages it, so its
plan drops e2e and the enumeration. The test-only change is where
selection pays for itself.

## Where the mapping comes from

No module of the tool lists a source. `tools/impact_read.py` reads them:

| Source | What it supplies |
| --- | --- |
| `make -qp` | every variable expanded, and every rule with its prerequisites and recipe |
| `make print-lib-srcs AXIS=...` | the sources each packaged object carries, one call per axis value |
| `proof/run.sh` | each harness's tier and the sources its launch line links |
| `proof/*_harness.c` | the module each harness includes, through its stubs header |
| `test/violations/*.violation` | the file each one edits and the target that must object |
| `test/*.sh` | the make command each gate wrapper execs, variables included, and the binaries `e2e.sh` runs |

So the mapping decays exactly when those stop naming their sources. A
recipe that hid a source list behind a variable it never mentions would
leave a gate unselected. That is why a Makefile edit selects everything,
and why the check below exists.

The rest of the tool is three more modules: `tools/impact_map.py` holds
what those readers found, `tools/impact_select.py` chooses the commands
for one changed path, and `tools/impact.py` is the command line.

## The check

`make lint-impact` runs `test/impact_test.py`, which reads
`test/violations/` as ground truth. Every violation records a file and
the target that objects when that file breaks, so for each one the check
asserts that the plan for that file selects that target. A miss is a bug
in the mapping, never in the check: teach the mapping where the gate
reads its sources, never drop the violation from the comparison.
`test/violations/inv19-webpki-object-frame.violation` is the sharpest
case: it takes a 5,000-byte frame in `p256.c`, and `PIN=rsa` keeps that
file out of every object but the `TRUST=webpki` one, so the check fails
unless the plan for `p256.c` selects `make lint-stack TRUST=webpki`.

The same check asserts that:

- every command the plan can emit names a make target the Makefile has
  or a file the tree holds;
- every command that links the packaged object names `RAND`, which has
  no default;
- a plan entry whose gate is a gate wrapper script runs the command that
  script execs, variables included;
- the everything plan runs every gate a narrow plan can select, so a
  Makefile edit is never checked less thoroughly than a one-source edit;
- each path the mapping refuses to narrow really does select every gate,
  a source no list in the tree names included.

It writes nothing in the working tree. The two checks that need a
changed set build one through a temporary git index and a scratch file
under `bin/`, so a run that is killed leaves no edited file behind.
