# Writing CBMC harnesses

How to write a harness that returns a verdict instead of eating the
machine. Every rule here comes from a measured failure in this
repository; the numbers are from CBMC 6.11.0 with kissat 4.0.4 on a
4-core, 16 GB container, under the exact flags `proof/run.sh` passes.
`proof/run.sh`'s header states what the suite checks and how the pool
schedules it; this file states how to write and size a new harness.

## The cost model

SAT cost tracks the number of multiplies in one formula, not the size
of the input domain.

- Solve time grows a little faster than the multiply count (measured
  exponent about 1.27); memory grows linearly with it. Halving the
  ML-KEM base multiplication's 64 pairs took 254 s / 3.6 GB down to
  105 s / 1.7 GB.
- One 128-butterfly NTT layer costs 56 s / 0.9 GB. Seven layers in one
  formula cost 195 s / 3.3 GB. The inverse NTT — about twice the
  multiplies — returns no verdict in 900 s as one formula, even with
  the signed-overflow class off. Split at the len 16/32 boundary, its
  halves prove in 349 s and 186 s with every check on.
- Merging the whole ML-KEM polynomial layer into one formula was
  killed by the kernel at 14 GB before the solver started.

So: one formula per concern, and when a formula holds more than
roughly a thousand multiplies, split it — along the multiply count,
not along file boundaries. handshake_parser/eeparse and the three ML-KEM
chained-product formulas are the precedents.

Division and modulo cost more than multiplies, and the C source does
not show it. CBMC builds them from the C, not from what the compiler
would emit, so `x % 4` on a `size_t` becomes a full 64-bit division circuit
even though the machine instruction is one `and`. `pem.c`'s base64 loop
computed a group position that way, once per input character: at an
unwind bound of 78 the formula returned no verdict in 120 s, and at
3138 it spent 73 minutes in symbolic execution without reaching the
solver. Writing the same expression as `x & 3U` verified the same formula
(537 properties, unwind 78, kissat) in 84 s. Prefer a mask for a power of two, and keep a symbolic divisor
out of a loop body.

Loop-carried state costs at every unwinding. The same loop tracked two
`size_t` running totals that only ever mattered mod 4 and against zero;
replacing them with a 2-bit position, a 0..2 counter and a flag cut
84 s to 62 s at the same unwind bound of 78, with no change to what
the C computes.
Size the state to what the algorithm needs, not to what is convenient.

## Rules

**Store nondet values through the object's own type.** Filling a
struct or an int16 array through a `(uint8_t *)` cast makes every
byte store a whole-object update in the SSA. About 2,500 such stores
are what OOMed the one-harness ML-KEM attempt at 14 GB; per-element
`p->coeffs[i] = nondet_i16()` loops fixed it. Byte-fills are fine for
real byte buffers and for small contexts (a 224-byte sponge).

**Havoc every operand freshly before every call.** A call that reads
a buffer the previous call wrote is proven only on that call's image —
reduced coefficients, just-encoded bytes — not on the domain the
harness claims. The one exception is a deliberate round trip, and then
the header comment must claim the round trip, not the full domain.

**Cover the aliasing shapes real callers use.** If the library calls
`mlk_poly_add(out, out, x)`, a harness that proves `add` only on
distinct pointers has not proven the caller. Grep the callers before
writing the harness's call list.

**Stubs assert the contract and havoc every output.** A stub that
leaves an output unhavocked proves less than the real function allows;
one that asserts more than callers guarantee fails falsely. The
harness that discharges a stub must drive the real function on a
superset of every caller's domain — full-range coefficients discharge
a full-range havoc.

**Full range is nearly free — keep it.** Bounding NTT inputs from all
of int16 to [0, q) saved 17% time and 3% memory. The wider theorem (no
UB on hostile or corrupted state) costs almost nothing, and the stub
discharge needs it.

**Write a power-of-two bound as bit structure, not as comparisons.** A
stub that returns a value in [-2^36, 2^36) can say so as
`(int64_t)(nondet_u64() << 27) >> 27`, a 37-bit sign extension, or as
`__CPROVER_assume(p > -2^36 && p < 2^36)`. Both mean the same set. The
x25519 ladder step, whose ten mul calls each take 256 such values,
proved in 540 s and 2.4 GB with the sign extension and in 1328 s and
4.1 GB with the comparisons: the solver reads the top 27 bits as
copies of bit 36 straight from the circuit, where the comparison form
makes it learn that from two 64-bit subtractions per value.

**Keep harness-reachable loop bounds concrete.** Unwinding a loop
whose trip count is a symbolic parameter copies the body to the
worst-case product of the nested bounds. A per-layer helper taking
`len` cannot be proven by unwinding for this reason; split at literal
boundaries instead, as `mlk_invntt_low`/`mlk_invntt_high` do.

**Fill a stub's output at a constant length where the contract allows
it.** A fill of `n` bytes, with `n` a symbolic value, unrolls to its
loop's whole bound, and every unrolled iteration is a guarded update
of the whole array that the formula keeps. The handshake drivers'
ClientHello stub filled `n <= 617` bytes that way, twice: 12.4 M of a
28.0 M-clause formula, measured by emptying the fill and reading
`--dimacs`'s header. The builder's contract bounds its writes only by
the caller's cap, so the stub now havocs all `cap` bytes -- a superset
of the real outputs, at a length that is a `sizeof` expression, which
symbolic execution unrolls to unguarded stores. The psk leg went from
1462 s at 5.9 GB of cbmc and 5.9 GB of kissat to 231 s at 1.6 GB and
7.8 GB, the pin leg from 415 s at 5.9 GB and 4.2 GB to 55 s at 1.1 GB
and 2.2 GB, with the same properties
(https://github.com/c4milo/chapulin/issues/140).

**A constant in the source is not always a constant to symbolic
execution.** The same drivers' record-reader stub fills
`t->cfg.buf_len` bytes, a value main() sets to 96, and that fill still
unrolled to the shared loop's 618-bound with a guard per store: the
session struct takes byte-pointer writes from the SHA-256 stub, and
after one its fields are expressions over the updated object, not
constants. With those fills on the shared loop, symbolic execution took
six times as long and 3.5 times the memory as with them on a loop of
their own bounded at 97. So when a fill's length reaches the stub as
anything but a literal or a `sizeof`, give it its own loop bounded by
its buffer -- handshake_record_harness.c's `fill_buf_nondet` and now
handshake_harness.c's -- and check `--dimacs`'s header rather than
the source to know which case a fill is in.

**A solver's peak is not a property of the formula alone.** kissat
solved one intermediate form of the psk driver formula six times -- two
cbmc builds, three DIMACS orderings of the same 28.0 M clauses -- and
peaked between 3.8 and 10.2 GB; the landed form has peaked at 3.6, 5.7
and 7.8 GB. Size the weight from the highest peak seen, and cut clauses
rather than chase a low reading.

**Measure, never estimate.** Run the candidate under
`/usr/bin/time -v` with the exact launch flags, including the solver
`run.sh` would pick. Record the peak and time in the launch-line
comment; set the weight at or above the measured peak. A verdict-less
harness proves nothing, and the README calls that out — never commit a
launch line whose formula has not been seen to converge.

**Name loops the goto model has.** Check every `--unwindset` id on a
launch line against `cbmc --show-loops` run on the same harness,
sources and `-D` flags. An id for a loop or a function the model does
not have bounds nothing, and the loop it was written for runs under
the global `--unwind` instead. cbmc only warns about it, so `run.sh`
and `coverage.py --reach` fail the launch on that warning
(https://github.com/c4milo/chapulin/issues/136). The fix is the id
`--show-loops` prints, or no entry when the loop is gone.

**Plant the bug the harness exists to catch, then land it.** A harness
that cannot fail proves nothing, and a passing run does not show which
kind it is. Apply the mutation by hand, run
`proof/prove-one.sh NAME` -- run.sh's exact launch for one harness,
exit nonzero unless it verifies, contract in its header -- and watch
the property fail. Then land the edit as a `test/violations/*.violation`
whose `catches` line names that same command, so the nightly keeps
checking that the proof still sees it; the two `inv24-*` files are the
precedent.

**Ask for the bound the caller needs, not for equality.** Equality of
two multipliers is the classic hard SAT instance: `ctwidemul`'s proof
that ct.h's 16x16 decomposition computes the native product converges
at 8-bit operands and returns no verdict at 16-bit in 900 s. The x25519
ladder proofs never need equality. Their contract on `ct_widemul_s` is
a magnitude bound, operands under 2^18 to a product under 2^36, and
that bound proves on the decomposition at the full operand range: 21 s
for the product block alone, 128 s and 1.7 GB for `x25519_mul_ct`, the
whole overflow lemma over it
(https://github.com/c4milo/chapulin/issues/145). When a stub states a
bound, discharge the bound on the shipped code; leave equality to the
proofs that read a value.

**Structure beats solver.** kissat returns verdicts where the built-in
solver has none after hours, so keep it installed. But no solver
rescues a monolithic formula: incremental z3 timed out on the same
base multiplication kissat solved in 254 s. If a formula does not
converge, restructure it; do not shop for solvers.

## When a formula will not converge

In order, with precedents:

1. **Split the harness** into more formulas over the same code
   (handshake_parser/eeparse; the ML-KEM fast/slow split).
2. **Split the code** at a literal boundary so each piece is one
   provable function (sha3's block-structured sponge;
   `mlk_invntt_low`/`mlk_invntt_high`). State in a comment that the
   split exists for the proof.
3. **Prove an arithmetic lemma per shape** with full checks and run
   the concrete harness without the class the lemma covers
   (x25519_mul, p256_mul, rsa_mul). Disclose the split in the README
   row; the lemma must cover every shape at every operand range the
   function can produce.
4. **Replace a callee with its contract** and prove the contract in
   the callee's own harness (aead over `proof/aead_stubs.h`;
   x25519_step and x25519_tail over `proof/x25519_stubs.h`). The stub
   header states what it models and what the composition gives up.
   This works when no property in the caller reads the callee's
   value beyond what the contract states: the ladder's properties are
   all bounds, so mul's multiply is a bound. A `static inline` callee
   in a header can be replaced without touching the source: include
   the header first under its own name, `#define` the name to the
   stub, then include the `.c`; the include guard keeps the `.c`'s own
   `#include` from reading the real definition again. A `static`
   function in the `.c` itself cannot be replaced this way, which is
   why the x25519 stub sits one level down, at `ct_widemul_s`, rather
   than at `mul`.
5. **Demote to the slow tier** and let CI's nightly budget carry it.
   A slow row's verdict comes from the last nightly, and the README
   says so.

## Prior art

mlkem-native proves the same mathematics with function contracts and
loop invariants written into the C source (`__contract__`/`__loop__`
macros that compile to nothing outside CBMC), one small obligation per
function, callees replaced by their contracts. That route keeps every
formula tiny and machine-checks the coefficient-bound ladder, at the
price of proof annotations and a ghost parameter living in the shipped
sources. chapulin keeps the shipped C free of verification tokens and
pays with solver time and the splitting rules above; both sides of the
trade are deliberate. Revisit their `proofs/cbmc/proof_guide.md` if
that trade ever changes.
