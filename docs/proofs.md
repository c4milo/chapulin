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

**Keep harness-reachable loop bounds concrete.** Unwinding a loop
whose trip count is a symbolic parameter copies the body to the
worst-case product of the nested bounds. A per-layer helper taking
`len` cannot be proven by unwinding for this reason; split at literal
boundaries instead, as `mlk_invntt_low`/`mlk_invntt_high` do.

**Measure, never estimate.** Run the candidate under
`/usr/bin/time -v` with the exact launch flags, including the solver
`run.sh` would pick. Record the peak and time in the launch-line
comment; set the weight at or above the measured peak. A verdict-less
harness proves nothing, and the README calls that out — never commit a
launch line whose formula has not been seen to converge.

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
4. **Demote to the slow tier** and let CI's nightly budget carry it.
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
