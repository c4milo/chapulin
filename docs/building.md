# Building

The Makefile targets and the build variables that choose what a packaged object carries.

`make check` runs the gate: build with warnings as errors, linters,
unit tests, end-to-end against OpenSSL and Go, the differential oracle,
and the fast proof tier.

Other targets:

- `make lib RAND=extern` packages the library as one relocatable object
  (`bin/chapulin.o`) exporting exactly the eight public calls and one data
  symbol, the build record `ch_build_info_tcp_blocking`. The eight are
  `ch_connect`, `ch_read`, `ch_write`, `ch_writable_len`, `ch_close`,
  `ch_ticket_obfuscated_age`, `ch_alert_sent` and `ch_alert_received`.
  Every internal symbol is
  localized, and `lib-check` fails if the export list ever changes. The
  calls are per build on three axes: `RAND=drbg` packages the reference
  generator and exports `ch_drbg_seed` and `ch_rand_bytes`, and a ca mode
  exports `ch_pubkey_from_pem` for provisioning, so a `TRUST=ca-rsa
  RAND=drbg` object exports eleven calls. `RAND=session` exports nothing
  more and imports no `ch_rand_bytes`: each session names its own source
  in `ch_cfg.rand_bytes` and `ch_cfg.rand_io`, which grow `ch_cfg`, and
  with it `ch_tls`, by two pointers, and every init call refuses a NULL
  `rand_bytes` (decision 77, [`docs/entropy.md`](entropy.md)). The build record, `ch_pubkey_from_pem`,
  a server's `ch_srv_check`, a client's `ch_ticket_obfuscated_age` and the
  two alert calls carry
  the transport in their symbol names (`ch_build_info_tcp_nonblocking`,
  `ch_srv_check_quic_nonblocking`), and the headers map the
  names you call to them, so one image links an object of each of two
  transports (decisions 61, 72 and 75, [`docs/porting.md`](porting.md)).
  `TRUST=webpki` exports the eight calls and no provisioning call.
  `EXPORTER=on` adds `ch_export`, the exporter of RFC 9846 §7.5, and 32
  bytes to `ch_tls`; it is off
  by default, so the figures in [`performance.md`](performance.md) are a build that exports nothing,
  and it refuses `TRANSPORT=quic-nonblocking`, whose object compiles no `tls.c`
  (decision 43). `KEYLOG=on` hands each traffic secret to a
  `ch_keylog` hook the image defines, for an NSS key log; it adds no
  export, it imports the hook, and it is refused for a client in a raw
  or ca trust mode (decision 44, INV-29). `WIDEMUL` is a device object's
  variable alone. `WIDEMUL=native` defines `CH_NATIVE_WIDEMUL` in the
  object: the builder states that this part's widening multiply runs in
  constant time, and every widening product then uses the CPU's multiply
  instead of 16x16 pieces (`ct.h`). The default, `WIDEMUL=decomposed`,
  makes no claim about the part. A host object, below, holds both
  multiplies and takes no `WIDEMUL` value, and the value
  `WIDEMUL=runtime`, which put both in an object when it was built, is
  gone (decisions 87 and 89).
  `TX_RECORD=N` sets `CH_TX_PT`, the most plaintext one outgoing record
  carries, to N bytes, a decimal integer from 512 to 16384; the peer's
  `record_size_limit` can still lower it. Empty, the default, leaves 512.
  A host that sends bulk data raises it to send fewer, larger records,
  and `ch_tls` grows to hold one sealed record: in stompy's `TRUST=webpki
  TRANSPORT=tcp-nonblocking ROLE=both` object it measures 17,280 bytes at
  `TX_RECORD=16384` against 3,280 at the default. It changes only what the
  object sends; `cfg.buf_len` still sets the records it receives. A QUIC
  object seals no TLS record, so `TRANSPORT=quic-nonblocking` refuses it
  (decision 71).
  `RAND` is the one build variable with no default: `extern`, `drbg` or
  `session`. Compose with
  `TRUST=raw-ecdsa`, `TRUST=ca-rsa` or `TRUST=webpki`, and `KEX=pq`;
  the `TRUST=webpki` object carries every verifier, which is why that
  value names no algorithm. No variable chooses the X25519 field: every
  object holds the 16-word one, a host object, below, also holds
  `x25519_wide.c`'s five 51-bit words, and the `X25519` variable, which
  chose the second for a whole object, is gone, so the Makefile and
  `build.zig` stop on any value of it (decisions 52 and 89, INV-34).
  No variable chooses the ChaCha20 keystream either: a device object
  runs `chacha20.c`'s one-block loop, a host object runs
  `chacha20_vector.c`'s eight blocks at a time on NEON or four on SSE2
  in every session, and the `CHACHA` variable, which chose the second for
  a whole object, is gone the same way (decisions 82 and 89). The
  `TRUST=webpki` object also carries every key
  exchange group it offers, X25519MLKEM768 and x25519 with a share each
  and secp256r1 listed after them for a HelloRetryRequest to ask for, so
  `make TRUST=webpki` refuses a `KEX` value, which would select nothing
  there (decisions 53 and 63); set `ch_cfg.require_pq` for the hybrid
  alone. `KEX` chooses the group of a raw or ca client only, and
  `ROLE=server` and `ROLE=both` refuse it too, because a server role
  holds all three groups in every build (decisions 54 and 63).
  `SUITE=aesgcm` adds `TLS_AES_128_GCM_SHA256` and
  `TLS_AES_256_GCM_SHA384` to a `TRUST=webpki` client or a server role.
  On an arm64 or x86-64 host that object is a host object, below, whose
  sessions run AES-GCM on the AES instructions and the carry-less
  multiply where your program sets `CH_CPU_CONSTANT_TIME_AES` (decisions
  50 and 89). A device object takes `AES=extern`: every AES block runs in
  a `ch_aes_block(key, key_len, in, out)` the image defines, 16-byte and
  32-byte keys both, and the build needs `-DCH_AES_EXTERN_CONSTANT_TIME`,
  the statement that the peripheral behind it runs in constant time
  (decision 68). The Makefile never writes that statement, `ct.h` refuses
  the suite on the `AES=soft` table, and nothing in this tree can check a
  peripheral. A host session with the AES bit offers and prefers
  `TLS_AES_256_GCM_SHA384`, then `TLS_AES_128_GCM_SHA256`, then ChaCha20,
  a host session without it offers ChaCha20 alone, and the `AES=extern`
  build keeps ChaCha20 first (decision 80). `AES` is a device object's
  variable alone: `soft`, the default, or `extern`. The Makefile and
  `build.zig` refuse an `AES` value for a host object, and the values
  `AES=hw` and `AES=runtime`, which chose the instructions when the object
  was built, are gone (decision 89).
- On an arm64 or x86-64 host, `TRUST=webpki`, `ROLE=server` and
  `ROLE=both` build a host object (decision 89). The Makefile and
  `build.zig` run the host test on the compiler: it targets arm64 or
  x86-64, NEON or SSE2 on a little-endian core, and has
  `unsigned __int128`. Where it passes, the object compiles with
  `-DCH_CPU_RUNTIME`, which `make print-lib-def` prints with the rest of
  its defines, and `ch_cfg` holds `cpu`, your description of the CPU
  (`cpu_cfg.h`). Your program probes the CPU and sets the bits it found in
  every session's configuration: `CH_CPU_PROBED` always, which says you
  wrote the field, `CH_CPU_CONSTANT_TIME_AES`,
  `CH_CPU_CONSTANT_TIME_MULTIPLY` and `CH_CPU_CONSTANT_TIME_SHA256` where
  you state those instructions run in constant time on that CPU in the
  mode your thread runs in, on x86-64 `CH_CPU_AVX2`, `CH_CPU_VAES` and
  `CH_CPU_AVX512_IFMA`, and on arm64 `CH_CPU_CONSTANT_TIME_SHA512` and
  `CH_CPU_CONSTANT_TIME_SHA3`. Every init call and `ch_srv_check` refuse a
  value without `CH_CPU_PROBED`, and one with a bit this object does not
  define for its architecture, such as `CH_CPU_AVX2` on arm64 or
  `CH_CPU_CONSTANT_TIME_SHA512` on x86-64. chapulin probes nothing and
  sets no CPU mode.
  The host object holds the AES instructions, and in a QUIC object the
  software AES beside them, and `CH_CPU_CONSTANT_TIME_AES` picks: with it
  the session runs the AES-GCM suites and QUIC's Initial packets on the
  instructions, and without it the session holds ChaCha20 alone, runs
  its Initial packets on the software AES, and init refuses a suite list
  that names an AES-GCM suite. The host object also holds each file built
  on the widening multiply twice, once on `ct.h`'s 16x16 decomposition and
  once on the CPU's multiply, so it is larger, and
  `CH_CPU_CONSTANT_TIME_MULTIPLY` picks for every operation of the
  session: Poly1305, ML-KEM and RSA signing (decision 87). X25519
  takes its second copy from another file: with the bit a session runs
  `x25519_wide.c`'s five 51-bit words on the 64x64->128 multiply, and
  without it the 16-word field on the decomposition, so the bit states
  the multiply at both widths (decisions 52 and 89). P-256 takes its
  second copy the same way: with the bit a session signs and exchanges
  keys on the four 64-bit words of `p256_wide_field.c` and
  `p256_wide_scalar.c`, and computes k·G from `p256_wide_table.c`'s
  86 KiB of multiples of the generator, and without it on
  `p256_field.c`'s and `p256_scalar.c`'s eight 32-bit words on the
  decomposition, with no table (decisions 94 and 109).
  RSA signing takes its second copy from another file too: with the bit
  a session signs with `rsa_sign64.c`, by the Chinese remainder theorem
  on 64-bit words from the five CRT integers a host object's
  `ch_rsa_priv` holds, and checks each signature before it returns it;
  without it, with `rsa_sign.c`'s ladder over n and d on the
  decomposition. Both RSA verifiers run on 64-bit words in every session
  of a host object, because they read no secret (decision 95).
  Set the bit when the multiply runs in constant time on the CPU and in
  the mode the session's thread runs in, which on arm64 means a core with
  FEAT_DIT and PSTATE.DIT set, and on x86-64 the DOITM policy of your
  operating system. Every host session runs ChaCha20 on
  `chacha20_vector.c`'s NEON or SSE2 passes, which every core of the two
  architectures has, so no bit picks them and the path states nothing
  about timing (decision 82). It runs ML-KEM's NTT and base
  multiplication on `mlkem_vector.c`'s eight 16-bit lanes the same way
  (decision 101).
  With the multiply bit the session's
  Poly1305 runs `poly1305_vector.c`'s four blocks at a time on the vector
  widening multiply, which the bit states beside the scalar one (decision
  83). On x86-64, `CH_CPU_AVX2` says the CPU has AVX2 and its operating
  system saves the 256-bit registers, and the session's ChaCha20 then
  runs `chacha20_avx2.c`'s kernel. `CH_CPU_VAES` says the CPU also has
  VAES and VPCLMULQDQ on those registers, and beside
  `CH_CPU_CONSTANT_TIME_AES`, whose statement covers the AES
  instructions at every width, AES-GCM's whole blocks then run
  `gcm_vaes.c`'s kernels (decision 90). `CH_CPU_AVX512_IFMA` says the CPU
  has AVX-512F and AVX-512 IFMA and its operating system saves the opmask
  and 512-bit registers. It states no timing, and no path reads it yet.
  Set each bit from your probe alone: a session whose bit names
  instructions its CPU lacks faults on the first one. The three hash
  bits say the CPU has the SHA-256, the SHA-512 or the SHA-3
  instructions, and state that they run in constant
  time in your thread's mode, as the AES bit does: on arm64 FEAT_SHA256,
  FEAT_SHA512 and FEAT_SHA3, and on x86-64 the SHA extensions with SSSE3
  and SSE4.1 for the SHA-256 bit alone (`cpu_cfg.h`). A session hands its
  `cpu` to every hash call of its transcript, its key schedule and its
  record and packet keys. With `CH_CPU_CONSTANT_TIME_SHA256` those calls
  run SHA-256, and HMAC, HKDF and the key schedule over it, on the
  instructions, in `sha256_hw.c` and the copies `hkdf_hw.c` and
  `keysched_hw.c`, which every host object holds beside the portable
  files. Without the bit they run `sha256.c`. With
  `CH_CPU_CONSTANT_TIME_SHA512` an arm64 session runs SHA-384, the hash
  of TLS_AES_256_GCM_SHA384, on the SHA-512 instructions, in
  `sha512_hw.c`, which a `SUITE=aesgcm` host object holds beside
  `sha512.c`, and without it on `sha512.c`. Each hash follows its own
  bit alone. A certificate's hash, a signature's and the DRBG's take no
  `cpu` and run the portable code in every object. Under
  `CH_CPU_CONSTANT_TIME_SHA3` an arm64 session runs SHA-3, SHAKE and
  ML-KEM on the SHA-3 instructions, in `sha3_hw.c` and ML-KEM's two
  copies over it, where clang compiled the object. In an object another
  compiler built, that bit picks nothing (decision 99). A raw or
  ca client builds the portable object on every target, and so does every
  product for any other target, so the default `make lib` has no `cpu`
  field. To package a server's portable object on a host, set the host
  test's result empty on the command line: `HOST_TARGET=` for make, and
  `-DHOST_TARGET=` for `zig build`.
- `ch_build` is the object's build record (`build.h`): the axes it was
  compiled with, the sizes of `ch_cfg`, `ch_tls`, `ch_ticket`,
  `ch_record`, `ch_quic` and `ch_rsa_priv`, and the bounds a program
  sizes its buffers from. A program that links the object compiles the
  headers under defines it writes itself, and a define it forgets
  changes those sizes while the program still links. So call
  `ch_build_matches(&ch_build)` once at startup and stop when it returns
  0; a program in another language compares the same fields with the
  `CH_BUILD_` macros. `ch_build` is a macro for the transport's record,
  `ch_build_info_tcp_blocking`, `ch_build_info_tcp_nonblocking` or `ch_build_info_quic_nonblocking`, and a Zig
  program names that record itself. No library call reads the record,
  and decisions 56 and 61 say what it holds, what it leaves out and why
  its name carries the transport.
- A Zig project (Zig 0.16.0) depends on chapulin as a package and gets
  the object `make lib` builds and a Zig API over it. The options are
  the Makefile's variables, with the same names and values, and the
  hardware statement the Makefile takes in `CFLAGS`,
  `CH_AES_EXTERN_CONSTANT_TIME`, is an option that defaults off.
  `TX_RECORD` takes its number, `.TX_RECORD = 16384`:

  ```zig
  const chapulin = b.dependency("chapulin", .{
      .target = target,
      .RAND = .@"extern",
      .TRANSPORT = .@"quic-nonblocking",
      .ROLE = .both,
      .TRUST = .webpki,
      .SUITE = .aesgcm,
  });
  module.addImport("chapulin", chapulin.module("chapulin"));
  ```

  The module `chapulin` is the Zig API, and it carries the object, so
  the program adds no `addObjectFile` of its own; a second one defines
  every public name twice. The program writes
  `const chapulin = @import("chapulin");`, calls
  `chapulin.buildMatches()` once, and runs sessions through
  `chapulin.record` or `chapulin.quic` ([`zig.md`](zig.md)). Under
  `.RAND = .session` each session's values carry a `std.Random`, and the
  program defines no `ch_rand_bytes`.
  `chapulin.c` is the public headers, translated by translate-c under the
  defines the object compiled with, so its types have the object's
  layout and the program names no define. An image that links objects
  of two transports takes two dependencies and imports each one's module
  under a name of its own. The named lazy path `chapulin.o` is the object
  and `include` the header directory, for a program that compiles the
  headers as C. `build.zig` compiles every source into one relocatable
  object, and `tools/localize_symbols.zig` makes every symbol but the
  public API local, as `objcopy -G` and `nmedit -s` do for make, so one
  image links objects of two transports. `make lint-zig-build` builds eight
  configurations both ways and requires the same sources, defines,
  exports and build record, and builds and runs Zig programs against
  each module (decisions 69, 70 and 73, INV-36).
- `make check` skips a lint, a Wycheproof test or a library build that
  passed before on the same inputs, and `make -j check` runs its lints,
  builds and test runs side by side. `tools/stamp.py` states what a
  skip keys on: the bytes of the files the check reads, the tools'
  versions, and the make and environment variables it runs under, never
  a time (INV-37). `CHECK_NO_STAMPS=1` runs every check. CI starts each
  job without `bin/`, so CI runs every check in full.
- `make check` builds, and does not run, each program a bench or
  platform script compiles from a source list of its own:
  `test/script-builds.sh` runs `bench/aead.sh --build`,
  `bench/record.sh --build`, `bench/primitives.sh --build` and
  `test/qemu-m3.sh --build`, and builds `bench/insn_driver.c` from the
  Makefile's `INSN_SRCS`. The lanes check does not run, such as
  `san-check`, `cross-check`, `m3-check` and `coverage`, compile each
  test from the variable its own rule reads (decision 88, INV-40).
- `make check-slow` runs `make check` and then three targets, which CI
  runs as three jobs beside its `check` job on every push to main and
  each night. `make ci-slow` runs the vectors over the decomposed
  multiply, the Zig build over every `lib-check` build, the crypto on an
  emulated Cortex-M3, `test/e2e.sh` against real servers, the spec
  differential and the sequence enumeration, and builds the binaries
  those steps run. `make ci-mutants` runs the fast tier of
  `test/violations/`. `make ci-prove` runs the fast-tier proofs. A CI
  job starts with no `bin/`, so none of the three needs `make check` to
  have run first. `make ci` runs `make check-slow`.
- `make prove-slow` runs the slow-tier proofs, one per nightly job. The runner caches by
  content, so an incremental run re-proves only what changed
  (`PROVE_NO_CACHE=1` forces a full run). It uses [kissat](https://github.com/arminbiere/kissat) when
  installed, which reaches the same verdicts faster;
  `PROVE_SOLVER=builtin` and `PROVE_SOLVER=smt2` pick the other back
  ends.
- `make timing` runs the constant-time check. Run it on an idle
  machine.
- `make fuzz` smoke-runs the libFuzzer harnesses.
- `make cxx-check` builds `chapulin.hpp`, an optional header-only C++
  wrapper. It forwards to the same C calls with no runtime cost, is
  freestanding, and compiles under `-fno-exceptions -fno-rtti`. It
  gives you a session that wipes its keys when it leaves scope.
- `make hooks`, once after clone, enables the commit-msg hook.

See [`CLAUDE.md`](../CLAUDE.md) for the house rules.
