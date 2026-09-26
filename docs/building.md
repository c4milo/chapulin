# Building

The Makefile targets and the build variables that choose what a packaged object carries.

`make check` runs the gate: build with warnings as errors, linters,
unit tests, end-to-end against OpenSSL and Go, the differential oracle,
and the fast proof tier.

Other targets:

- `make lib RAND=extern` packages the library as one relocatable object
  (`bin/chapulin.o`) exporting exactly the four public calls and one data
  symbol, the build record `ch_build_info_tcp_blocking`. Every internal symbol is
  localized, and `lib-check` fails if the export list ever changes. The
  calls are per build on three axes: `RAND=drbg` packages the reference
  generator and exports `ch_drbg_seed` and `ch_rand_bytes`, and a ca mode
  exports `ch_pubkey_from_pem` for provisioning, so a `TRUST=ca-rsa
  RAND=drbg` object exports seven calls. The build record, `ch_pubkey_from_pem` and
  a server's `ch_srv_check` carry the transport in their symbol names
  (`ch_build_info_tcp_nonblocking`, `ch_srv_check_quic_nonblocking`), and the headers map the
  names you call to them, so one image links an object of each of two
  transports (decision 61, [`docs/porting.md`](porting.md)).
  `TRUST=webpki` exports the four calls and no provisioning call.
  `EXPORTER=on` adds `ch_export`, the exporter of RFC 9846 §7.5, and 32
  bytes to `ch_tls`; it is off
  by default, so the figures in [`performance.md`](performance.md) are a build that exports nothing,
  and it refuses `TRANSPORT=quic-nonblocking`, whose object compiles no `tls.c`
  (decision 43). `KEYLOG=on` hands each traffic secret to a
  `ch_keylog` hook the image defines, for an NSS key log; it adds no
  export, it imports the hook, and it is refused for a client in a raw
  or ca trust mode (decision 44, INV-29). `WIDEMUL=native` defines
  `CH_NATIVE_WIDEMUL` in the object: the builder states that this
  part's widening multiply runs in constant time, and every widening
  product then uses the CPU's multiply instead of 16x16 pieces (`ct.h`).
  The default, `WIDEMUL=decomposed`, makes no claim about the part.
  `TX_RECORD=N` sets `CH_TX_PT`, the most plaintext one outgoing record
  carries, to N bytes, a decimal integer from 512 to 16384; the peer's
  `record_size_limit` can still lower it. Empty, the default, leaves 512.
  A host that sends bulk data raises it to send fewer, larger records,
  and `ch_tls` grows to hold one sealed record: in stompy's `TRUST=webpki
  TRANSPORT=tcp-nonblocking ROLE=both` object it measures 17,264 bytes at
  `TX_RECORD=16384` against 3,264 at the default. It changes only what the
  object sends; `cfg.buf_len` still sets the records it receives. A QUIC
  object seals no TLS record, so `TRANSPORT=quic-nonblocking` refuses it
  (decision 71).
  `RAND` is the one build variable with no default. Compose with
  `TRUST=raw-ecdsa`, `TRUST=ca-rsa` or `TRUST=webpki`, and `KEX=pq`;
  the `TRUST=webpki` object carries every verifier, which is why that
  value names no algorithm. `X25519=wide` replaces the default 16-limb
  X25519 field with `x25519_wide.c`'s five 51-bit limbs, for a 64-bit
  host: `ct.h` stops the build unless the compiler has
  `unsigned __int128` and the build adds `-DCH_NATIVE_MUL128` to
  `CFLAGS`, its statement that the part's 64x64->128 multiply runs in
  constant time in the mode the part runs in (decision 52, INV-34). The
  Makefile never writes that define itself. It also carries every key
  exchange group it offers, X25519MLKEM768 and x25519 with a share each
  and secp256r1 listed after them for a HelloRetryRequest to ask for, so
  `make TRUST=webpki` refuses a `KEX` value, which would select nothing
  there (decisions 53 and 63); set `ch_cfg.require_pq` for the hybrid
  alone. `KEX` chooses the group of a raw or ca client only, and
  `ROLE=server` and `ROLE=both` refuse it too, because a server role
  holds all three groups in every build (decisions 54 and 63).
  `SUITE=aesgcm` adds `TLS_AES_128_GCM_SHA256` and
  `TLS_AES_256_GCM_SHA384` to a `TRUST=webpki` client or a server role,
  and it takes one of two `AES` values. `AES=hw` runs AES on the
  compiler's intrinsics and needs `-DCH_NATIVE_AES` in `CFLAGS`, the
  statement that the part's AES instructions and carry-less multiply run
  in constant time (decision 50). `AES=extern` runs every AES block in a
  `ch_aes_block(key, key_len, in, out)` the image defines, 16-byte and
  32-byte keys both, and needs `-DCH_AES_EXTERN_CONSTANT_TIME`, the
  statement that the peripheral behind it runs in constant time
  (decision 68). The Makefile writes neither statement, `ct.h` refuses
  the suite without the one its `AES` value needs, and nothing in this
  tree can check either.
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
  the object `make lib` builds and a module of its API. The options are
  the Makefile's variables, with the same names and values, and the
  three hardware statements the Makefile takes in `CFLAGS` are options
  that default off. `TX_RECORD` takes its number, `.TX_RECORD = 16384`:

  ```zig
  const chapulin = b.dependency("chapulin", .{
      .target = target,
      .RAND = .@"extern",
      .TRANSPORT = .@"quic-nonblocking",
      .ROLE = .both,
      .TRUST = .webpki,
      .SUITE = .aesgcm,
      .AES = .hw,
      .CH_NATIVE_AES = true,
  });
  module.addImport("chapulin", chapulin.module("chapulin"));
  module.addObjectFile(chapulin.namedLazyPath("chapulin.o"));
  ```

  The module `chapulin` is the public headers, translated by translate-c
  under the defines the object compiled with, so its types have the
  object's layout and the program names no define. The program writes
  `const c = @import("chapulin");` and calls
  `c.ch_build_matches(&c.ch_build_info_quic_nonblocking)` once. It names
  the transport's record because Zig cannot evaluate the `ch_build`
  macro. An image that links objects of two transports takes two
  dependencies and imports each one's module under a name of its own. The
  named lazy path `include` is the header directory, for a program that
  compiles the headers as C. `build.zig` compiles every source into one
  relocatable object, and `tools/localize_symbols.zig` makes every symbol
  but the public API local, as `objcopy -G` and `nmedit -s` do for make,
  so one image links objects of two transports. `make lint-zig-build`
  builds five configurations both ways and requires the same sources,
  defines, exports and build record, and builds a Zig program against
  each module (decisions 69 and 70, INV-36).
- `make check` skips a lint, a Wycheproof leg or a packaged-object leg
  that passed before on the same inputs, and `make -j check` runs its
  lints, legs and test runs side by side. `tools/stamp.py` states what a
  skip keys on: the bytes of the files the check reads, the tools'
  versions, and the make and environment variables it runs under, never
  a time (INV-37). `CHECK_NO_STAMPS=1` runs every check. CI starts each
  job without `bin/`, so CI runs every check in full.
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
