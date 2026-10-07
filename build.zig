//! The Zig build of the object `make lib` packages, for a Zig project that
//! depends on chapulin as a package (docs/decisions.md 69).
//!
//! The Makefile is the source of truth. Each option is a Makefile variable
//! with its name and values, and computePlan builds LIB_SRCS, LIB_DEF and
//! PUBLIC as the Makefile does, one function per axis block. `make
//! lint-zig-build` builds configurations both ways and requires the same
//! sources, defines and exports.
//!
//! The sources compile into one relocatable object, as `ld -r` links them
//! for `make lib`, and tools/localize_symbols.zig then makes every defined
//! symbol local except PUBLIC, as `objcopy -G` and `nmedit -s` do.
//!
//! A dependent gets the module "chapulin", the Zig API (docs/zig.md), which
//! carries the object and declares the public headers as chapulin.c,
//! translated by translate-c under the defines the object compiled with
//! (docs/decisions.md 70 and 73); the named lazy path "chapulin.o", the
//! localized object, for a program that compiles the headers as C; and
//! "include", the directory of the headers. It calls
//! chapulin.buildMatches once (build.h).
const std = @import("std");

const Transport = enum { @"tcp-blocking", @"tcp-nonblocking", @"quic-nonblocking" };
const Role = enum { client, server, both };
const Trust = enum { @"raw-rsa", @"raw-ecdsa", @"ca-rsa", @"ca-ecdsa", webpki, none };
const Suite = enum { chacha, aesgcm };
const Aes = enum { soft, @"extern" };
const Rand = enum { @"extern", drbg, session };
const Kex = enum { x25519, pq };
const Widemul = enum { decomposed, native };
const Setting = enum { on, off };

/// The build variables, with the Makefile's defaults. rand and kex have no
/// default: the Makefile gives RAND none, and it tells a KEX value the
/// command line set from its default.
const Config = struct {
    transport: Transport,
    role: Role,
    trust: Trust,
    suite: Suite,
    aes: ?Aes,
    rand: ?Rand,
    kex: ?Kex,
    widemul: ?Widemul,
    exporter: Setting,
    keylog: Setting,
    /// TX_RECORD as the Makefile takes it, the text of a decimal integer,
    /// and null for the default, cfg.h's 512.
    tx_record: ?[]const u8,
    /// HOST_TARGET as the Makefile takes it: the host test's result, which a
    /// check sets on its own command line to package a device object on a
    /// development machine. Empty says the target failed the test, any
    /// other text that it passed, and null runs the test on the target.
    host_target: ?[]const u8,
    /// The hardware statement ct.h reads beside WIDEMUL=native's. The
    /// Makefile never writes it into a library build, and a builder adds
    /// it to CFLAGS. It defaults off here for the same reason: it is a
    /// claim about the part that only the firmware author can make.
    aes_extern_constant_time: bool,
};

const Names = []const []const u8;

/// LIB_SRCS, LIB_DEF with the hardware statements after it, PUBLIC, and
/// the headers that declare PUBLIC's names and the hooks the object
/// imports, which chapulin.c is translated from.
const Plan = struct { srcs: Names, defs: Names, public: Names, headers: Names };

/// What one axis block of the Makefile sets: its defines, the sources it
/// filters out of SRCS, the sources it adds, and its public calls.
const Axis = struct { defs: Names = &.{}, filter: Names = &.{}, add: Names = &.{}, public: Names = &.{} };

// SRCS in the Makefile, in its order.
const srcs = [_][]const u8{
    "ct.c",               "ct_wipe.c",             "sha256.c",           "hkdf.c",
    "chacha20.c",         "poly1305.c",            "aead.c",             "x25519.c",
    "p256.c",             "rsa.c",                 "rsa_mont.c",         "pem.c",
    "x509.c",             "x509_der.c",            "x509_ca.c",          "webpki_time.c",
    "webpki_name.c",      "webpki_spki.c",         "webpki_ext.c",       "buf.c",
    "record.c",           "keysched.c",            "io.c",               "handshake_message.c",
    "handshake_parser.c", "handshake_parser_ee.c", "handshake_record.c", "session.c",
    "handshake_auth.c",   "handshake_flight.c",    "handshake.c",        "handshake_post.c",
    "tls.c",              "tls_write.c",           "softmul.c",          "build.c",
};

// The Makefile's named lists, each under its Makefile name.
const aes_hw_srcs = [_][]const u8{ "aes_hw.c", "ghash_hw.c", "gcm_hw.c", "gcm_vaes.c" };
const quic_srcs_after_aes = [_][]const u8{
    "gcm.c",         "quic_keys.c", "quic_packet.c", "quic_initial.c", "quic_retry.c",
    "quic_config.c", "quic_fail.c", "quic_step.c",   "quic.c",
};
const srv_srcs = [_][]const u8{
    "srv_ticket.c", "srv_parser.c", "srv_parser_ext.c", "srv_message.c",
    "srv_cookie.c", "srv_auth.c",   "srv_out.c",        "srv_resume.c",
    "srv_kex.c",    "srv_flight.c", "srv_handshake.c",  "srv.c",
};
const client_replaced = [_][]const u8{
    "handshake.c",           "handshake_auth.c",    "handshake_parser.c",
    "handshake_parser_ee.c", "handshake_message.c", "handshake_flight.c",
};
const webpki_srcs = [_][]const u8{
    "webpki_time.c", "webpki_name.c", "webpki_spki.c",   "webpki_sigalg.c", "webpki_ext.c",
    "webpki_cert.c", "webpki.c",      "webpki_ticket.c", "webpki_pin.c",    "webpki_cfg.c",
};
const webpki_chain_srcs = [_][]const u8{ "sha512.c", "sha512_compress.c", "p384.c", "p384_field.c", "rsa_pkcs1.c" };
const p256_ecdh_srcs = [_][]const u8{ "p256_ecdh.c", "p256_point.c", "p256_scalar.c", "p256_field.c" };
const webpki_kex_srcs = [_][]const u8{"handshake_groups.c"} ++ p256_ecdh_srcs;
const quic_replaced = [_][]const u8{ "io.c", "record.c", "session.c", "handshake.c", "tls.c", "tls_write.c" };
const kex_hybrid_srcs = [_][]const u8{ "sha3.c", "mlkem.c", "mlkem_poly.c" };
/// WIDEMUL_COPIED: the files built on ct.h's widening multiply that a
/// host object compiles a second time, as <file>_native.c. x25519.c,
/// p256_field.c, p256_scalar.c and rsa_sign.c are not among them: their
/// second copies are x25519_wide.c's field, the wide P-256 files and
/// rsa_sign64.c's limbs.
const widemul_copied = [_][]const u8{ "poly1305.c", "mlkem_poly.c" };
/// P256_WIDE_SRCS: the wide P-256 files a host object holds beside
/// p256_point.c (docs/decisions.md 94, 96 and 104).
const p256_wide_srcs = [_][]const u8{
    "p256_wide_field.c", "p256_wide_scalar.c", "p256_wide_point.c",  "p256_wide_mul.c",
    "p256_wide_table.c", "p256_wide_wipe.c",   "p256_wide_verify.c", "p256_wide_verify_point.c",
};
/// P384_WIDE_SRCS: P-384's field, points and verifier on six 64-bit
/// limbs, which a host object holds beside p384.c (docs/decisions.md 97).
const p384_wide_srcs = [_][]const u8{ "p384_wide_field.c", "p384_wide_point.c", "p384_wide_verify.c" };
/// TRUST_FILTER's first four names, which every mode but webpki and the
/// ca modes filters out.
const certificate_srcs = [_][]const u8{ "pem.c", "x509.c", "x509_der.c", "x509_ca.c" };
/// ROLE_ADD before a transport swaps the server's driver.
const server_add = srv_srcs ++ [_][]const u8{ "rsa_sign.c", "p256_sign.c" } ++ p256_ecdh_srcs;

// PUBLIC_TRANSPORT and PUBLIC_ROLE's lists.
const public_quic = [_][]const u8{
    "ch_quic_init",               "ch_quic_initial_keys",       "ch_quic_crypto_in",  "ch_quic_crypto_out",
    "ch_quic_switch_version",     "ch_quic_negotiated_version", "ch_quic_seal",       "ch_quic_seal_close",
    "ch_quic_open",               "ch_quic_retry_ok",           "ch_quic_key_update", "ch_quic_key_phase",
    "ch_quic_drop_previous_keys", "ch_quic_discard",            "ch_quic_state",      "ch_quic_alert",
    "ch_quic_error_code",         "ch_quic_close",
};
/// The client's ticket age call, which every client object exports over
/// every transport.
const public_ticket = [_][]const u8{"ch_ticket_obfuscated_age"};
/// The two calls alert.h declares, which every object exports, whatever
/// its transport and role.
const public_alert = [_][]const u8{ "ch_alert_sent", "ch_alert_received" };
const public_tcp_nonblocking = [_][]const u8{
    "ch_record_init",  "ch_record_in",        "ch_record_out", "ch_record_state",
    "ch_record_close", "ch_record_whole_len", "ch_read",       "ch_write",
    "ch_writable_len", "ch_close",
} ++ public_ticket ++ public_alert;
const public_tcp_blocking = [_][]const u8{ "ch_connect", "ch_read", "ch_write", "ch_writable_len", "ch_close" } ++ public_ticket ++ public_alert;
const public_srv_quic = [_][]const u8{
    "ch_srv_quic_init",       "ch_srv_quic_crypto_in",   "ch_srv_quic_retry_tag",
    "ch_srv_quic_token_mint", "ch_srv_quic_token_check", "ch_srv_check",
};
const public_srv_tcp_nonblocking = [_][]const u8{ "ch_srv_record_init", "ch_srv_record_in", "ch_srv_check" };
const public_srv_tcp_blocking = [_][]const u8{ "ch_srv_accept", "ch_srv_check" };
/// The packet calls quic.h declares for either role, which a ROLE=server
/// QUIC object exports without the client's driver.
const public_quic_either_role = [_][]const u8{
    "ch_quic_initial_keys",       "ch_quic_negotiated_version", "ch_quic_seal",       "ch_quic_seal_close",
    "ch_quic_open",               "ch_quic_retry_ok",           "ch_quic_key_update", "ch_quic_key_phase",
    "ch_quic_drop_previous_keys", "ch_quic_discard",            "ch_quic_state",      "ch_quic_alert",
    "ch_quic_error_code",         "ch_quic_close",
} ++ public_alert;
/// The calls a connected tcp-nonblocking session makes, which a ROLE=server
/// object exports without the client's driver.
const public_record_either_role = [_][]const u8{
    "ch_record_state", "ch_record_close", "ch_record_whole_len", "ch_read",
    "ch_write",        "ch_writable_len", "ch_close",
} ++ public_alert;
/// The calls a connected tcp-blocking session makes.
const public_session = [_][]const u8{ "ch_read", "ch_write", "ch_writable_len", "ch_close" } ++ public_alert;

/// One header and the names it declares.
const Declaration = struct { header: []const u8, names: Names };

/// The header that declares each name an object can export, under the name
/// the header declares, and each hook an object can import from the image
/// (docs/porting.md). chapulin.c is translated from the headers of the
/// names one object exports and imports, in this order, and a name missing
/// here stops the build (headersDeclaring).
const declarations = [_]Declaration{
    .{ .header = "tls.h", .names = &.{ "ch_connect", "ch_read", "ch_write", "ch_writable_len", "ch_close", "ch_export" } },
    .{ .header = "tcp_nonblocking.h", .names = &.{
        "ch_record_init",  "ch_record_in",    "ch_record_out",
        "ch_record_state", "ch_record_close", "ch_record_whole_len",
    } },
    .{ .header = "quic.h", .names = &public_quic },
    .{ .header = "srv.h", .names = &.{ "ch_srv_accept", "ch_srv_check" } },
    .{ .header = "srv_tcp_nonblocking.h", .names = &.{ "ch_srv_record_init", "ch_srv_record_in" } },
    .{ .header = "srv_quic.h", .names = &.{ "ch_srv_quic_init", "ch_srv_quic_crypto_in", "ch_srv_quic_retry_tag" } },
    .{ .header = "quic_token.h", .names = &.{ "ch_srv_quic_token_mint", "ch_srv_quic_token_check" } },
    .{ .header = "x509_ca.h", .names = &.{"ch_pubkey_from_pem"} },
    .{ .header = "ticket.h", .names = &public_ticket },
    .{ .header = "alert.h", .names = &public_alert },
    .{ .header = "drbg.h", .names = &.{"ch_drbg_seed"} },
    .{ .header = "rand.h", .names = &.{"ch_rand_bytes"} },
    .{ .header = "keylog.h", .names = &.{"ch_keylog"} },
    .{ .header = "aes_block.h", .names = &.{"ch_aes_block"} },
    .{ .header = "ch_assert.h", .names = &.{"ch_assert_fail"} },
    .{ .header = "build.h", .names = &.{"ch_build"} },
};

/// The flags every source compiles with besides the defines: LIB_CFLAGS,
/// with the host test declarations filtered out as the Makefile filters
/// them. -O2 is not among them because the module's optimize mode passes
/// it (ReleaseFast below).
///
/// Zig passes flags of its own that make's cc does not, and cc applies
/// defaults Zig does not. None of them changes what the object computes or
/// exports, and none of them is a -D chapulin reads:
///
/// - -DNDEBUG. No source or header here reads it; CH_ASSERT is ch_assert.h's
///   and stays on in every build.
/// - -fPIC and a kept frame pointer. They change code generation, not
///   behavior, and an object compiled -fPIC links into a position
///   independent executable, a shared library or a static image alike.
/// - no stack protector, which Apple's clang and Ubuntu's gcc turn on by
///   default, and on Linux no _FORTIFY_SOURCE, which Ubuntu's gcc defines
///   by default and Zig's glibc headers leave off. The Makefile asks for
///   neither, and each adds checks a program without a memory error never
///   fails.
/// - the target's CPU features. Zig compiles for the target the dependent
///   passes, which is the machine it builds on unless it says otherwise,
///   and make compiles for its cc's default CPU.
const cflags = [_][]const u8{
    "-std=c11", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-Wvla",
};

pub fn build(b: *std.Build) void {
    const config = Config{
        .transport = b.option(Transport, "TRANSPORT", "What TLS runs over and who does the I/O") orelse .@"tcp-blocking",
        .role = b.option(Role, "ROLE", "client, server, or both for a host") orelse .client,
        .trust = b.option(Trust, "TRUST", "How the server key is trusted; none for ROLE=server") orelse .@"raw-rsa",
        .suite = b.option(Suite, "SUITE", "chacha, or aesgcm for the AES-GCM suites beside it") orelse .chacha,
        .aes = b.option(Aes, "AES", "A device object's AES: soft, or extern for the image's ch_aes_block"),
        .rand = b.option(Rand, "RAND", "The entropy pattern, which has no default (cfg.h)"),
        .kex = b.option(Kex, "KEX", "The key exchange group of a raw or ca client"),
        .widemul = b.option(Widemul, "WIDEMUL", "A device object's widening multiply (ct.h): decomposed, or native"),
        .exporter = b.option(Setting, "EXPORTER", "ch_export, RFC 9846 section 7.5") orelse .off,
        .keylog = b.option(Setting, "KEYLOG", "The ch_keylog hook (keylog.h)") orelse .off,
        .tx_record = nonEmpty(b.option([]const u8, "TX_RECORD", "The most plaintext one outgoing TLS record carries, 512 to 16384 (cfg.h's CH_TX_PT)")),
        .host_target = b.option([]const u8, "HOST_TARGET", "The host test's result, for a check: empty builds the device object on a host target"),
        .aes_extern_constant_time = b.option(bool, "CH_AES_EXTERN_CONSTANT_TIME", "State that ch_aes_block runs in constant time (ct.h)") orelse false,
    };
    refuseUnbuildable(config);
    const target = b.standardTargetOptions(.{});
    refuseSpeedOnHost(config, target.result);
    const plan = computePlan(b, config, target.result);
    // The flags the sources compile with. The module below is translated
    // under every -D among them, so the object and the module take their
    // defines from this one list.
    const flags = concat(b, &.{ &cflags, plan.defs });

    // The sources, compiled and partially linked into one object. make lib
    // compiles at -O2, and ReleaseFast passes -O2 to clang. The C sources
    // see none of Zig's safety modes: sanitize_c, stack_protector and
    // stack_check are off. strip leaves out the debugging information make
    // lib does not ask for either.
    const module = b.createModule(.{
        .target = target,
        .optimize = .ReleaseFast,
        .link_libc = true,
        .strip = true,
        .sanitize_c = .off,
        .stack_protector = false,
        .stack_check = false,
    });
    module.addIncludePath(b.path(""));
    module.addCSourceFiles(.{ .files = plan.srcs, .flags = flags });
    const partial = b.addObject(.{ .name = "chapulin-partial", .root_module = module });

    // The localizer runs on the host; test/localize-check.sh installs it.
    const localizer = b.addExecutable(.{
        .name = "localize_symbols",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/localize_symbols.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    b.step("localize-symbols", "Install the localizer to bin/").dependOn(&b.addInstallArtifact(localizer, .{}).step);
    const unit_tests = b.addTest(.{ .root_module = localizer.root_module });
    b.step("test", "Run the localizer's unit tests").dependOn(&b.addRunArtifact(unit_tests).step);
    const localize = b.addRunArtifact(localizer);
    localize.addFileArg(partial.getEmittedBin());
    const object = localize.addOutputFileArg("chapulin.o");
    localize.addArgs(plan.public);
    b.addNamedLazyPath("chapulin.o", object);
    b.getInstallStep().dependOn(&b.addInstallFile(object, "lib/chapulin.o").step);

    // make lib compiles with -I. at the root, where every header sits.
    b.addNamedLazyPath("include", b.path(""));

    // The headers of the plan, translated by translate-c for the object's
    // target and optimize mode under the defines in flags, so a dependent's
    // types have the object's layout (docs/decisions.md 70). chapulin.h is
    // written here and includes each header. Nothing runs the translation
    // until a dependent imports the module below. Neither module sets a
    // target or an optimize mode, so each takes both from the module that
    // imports it.
    const translate = b.addTranslateC(.{
        .root_source_file = b.addWriteFiles().add("chapulin.h", includes(b, plan.headers)),
        .target = target,
        .optimize = .ReleaseFast,
    });
    translate.addIncludePath(b.path(""));
    for (flags) |flag| {
        if (std.mem.startsWith(u8, flag, "-D")) translate.defineCMacroRaw(flag["-D".len..]);
    }
    const translated = b.createModule(.{ .root_source_file = translate.getOutput(), .link_libc = true });

    // The module "chapulin": the Zig API (chapulin.zig, docs/zig.md), which
    // imports the translated headers as "chapulin_c" and declares them as
    // chapulin.c. Zig refuses one file in two modules of one program, and
    // a program that links objects of two transports imports two of these
    // modules, so the API's files are copied into a directory of this
    // configuration's own. defines.txt, the object's define list, is what
    // makes two configurations' directories differ (docs/decisions.md 73).
    const api_files = b.addWriteFiles();
    const root = api_files.addCopyFile(b.path("chapulin.zig"), "chapulin.zig");
    _ = api_files.addCopyFile(b.path("chapulin_record.zig"), "chapulin_record.zig");
    _ = api_files.addCopyFile(b.path("chapulin_quic.zig"), "chapulin_quic.zig");
    _ = api_files.addCopyFile(b.path("chapulin_ticket.zig"), "chapulin_ticket.zig");
    _ = api_files.add("defines.txt", lines(b, plan.defs));
    const api = b.addModule("chapulin", .{
        .root_source_file = root,
        .imports = &.{.{ .name = "chapulin_c", .module = translated }},
    });
    // The module carries the object, so a program links it by importing
    // the module, once however many of its modules import it, and adds no
    // object of its own: a second addObjectFile of the same object defines
    // every public name twice.
    api.addObjectFile(object);

    // What make lint-zig-build compares with make print-lib-srcs and make
    // print-lib-def, one name per line, and the headers chapulin.c is
    // translated from, which tools/public-constants.py reads.
    const lists = b.addWriteFiles();
    const lists_step = b.step("lib-lists", "Install lib-srcs.txt, lib-def.txt and lib-headers.txt, the object's sources, defines and public headers");
    lists_step.dependOn(&b.addInstallFile(lists.add("lib-srcs.txt", lines(b, plan.srcs)), "lib-srcs.txt").step);
    lists_step.dependOn(&b.addInstallFile(lists.add("lib-def.txt", lines(b, plan.defs)), "lib-def.txt").step);
    lists_step.dependOn(&b.addInstallFile(lists.add("lib-headers.txt", lines(b, plan.headers)), "lib-headers.txt").step);
}

/// Every $(error) the Makefile's axis blocks raise for a combination of
/// values, in the Makefile's order and with its words.
fn refuseUnbuildable(config: Config) void {
    const fatal = std.process.fatal;
    const client_trusts = "use TRUST=raw-rsa, TRUST=raw-ecdsa, TRUST=ca-rsa, TRUST=ca-ecdsa or TRUST=webpki";
    switch (config.role) {
        .server => if (config.trust != .none)
            fatal("ROLE=server judges no peer certificate, so it has no trust mode to choose; use TRUST=none", .{}),
        .both => if (config.trust == .none)
            fatal("ROLE=both carries a client, which judges a peer certificate; TRUST=none is ROLE=server only, so " ++ client_trusts, .{}),
        .client => if (config.trust == .none)
            fatal("TRUST=none is the ROLE=server value; a client judges a peer certificate, so " ++ client_trusts, .{}),
    }
    if (config.kex != null and !deviceClient(config)) {
        fatal("KEX={t} chooses the group of a raw or ca client, and TRUST={t} ROLE={t} is not one: a TRUST=webpki " ++
            "client offers X25519MLKEM768 and x25519 in every build, and a server role holds both in every build " ++
            "(docs/decisions.md 53 and 54). Drop KEX, and set ch_cfg.require_pq for the hybrid alone", .{ config.kex.?, config.trust, config.role });
    }
    if (config.exporter == .on and config.transport == .@"quic-nonblocking") {
        fatal("EXPORTER=on has no QUIC entry point: ch_export is a record-layer call, so use TRANSPORT=tcp-blocking or TRANSPORT=tcp-nonblocking", .{});
    }
    if (config.keylog == .on and config.role == .client and config.trust != .webpki) {
        fatal("KEYLOG=on is refused for a device client: use TRUST=webpki, ROLE=server or ROLE=both", .{});
    }
    if (config.suite == .aesgcm and config.role == .client and config.trust != .webpki) {
        fatal("SUITE=aesgcm is refused for a device client: use TRUST=webpki, ROLE=server or ROLE=both", .{});
    }
    if (config.tx_record) |text| {
        if (config.transport == .@"quic-nonblocking") {
            fatal("TX_RECORD={s} sizes a TLS record, and TRANSPORT=quic-nonblocking seals none: drop TX_RECORD, or use TRANSPORT=tcp-blocking or TRANSPORT=tcp-nonblocking", .{text});
        }
        if (!recordSize(text)) {
            fatal("TX_RECORD={s} is not a record size; use a decimal integer from 512 to 16384, or leave TX_RECORD empty for 512", .{text});
        }
    }
}

/// An option the Makefile reads as unset when it is empty.
fn nonEmpty(text: ?[]const u8) ?[]const u8 {
    const value = text orelse return null;
    return if (value.len == 0) null else value;
}

/// Whether text is a value the Makefile's TX_RECORD takes: a decimal
/// integer with no leading zero, from 512 to 16384. The define repeats the
/// text, and C reads a leading zero as octal, so the rule is the text's
/// and not only the number's.
fn recordSize(text: []const u8) bool {
    if (text.len == 0 or text[0] == '0') return false;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    const n = std.fmt.parseInt(u32, text, 10) catch return false;
    return n >= 512 and n <= 16384;
}

/// The Makefile's refusals of a speed value for a host object, which holds
/// each fast path beside the portable code and lets each session pick from
/// ch_cfg.cpu (docs/decisions.md 89). AES and WIDEMUL choose a device
/// object's AES and multiply. A host object holds the AES instructions, and
/// in a QUIC object the table beside them, and both multiplies. The values
/// that chose a fast path when the object was built are gone, so Aes and
/// Widemul do not name them, and zig build refuses them as it refuses any
/// other value. The X25519 and CHACHA options are gone whole, so zig build
/// refuses each as it refuses any option this file does not declare: a host
/// object holds the wide field, which each session's multiply bit picks,
/// and runs the vector ChaCha20 in every session.
fn refuseSpeedOnHost(config: Config, target: std.Target) void {
    if (!hostObject(config, target)) return;
    const builds = "on this target builds a host object, which ";
    const device = ", or build the device object: a device target, or HOST_TARGET set empty";
    if (config.aes) |aes| {
        std.process.fatal("AES={t} chooses a device object's AES, and TRUST={t} ROLE={t} " ++ builds ++
            "holds the AES instructions and picks them per session from ch_cfg.cpu " ++
            "(docs/decisions.md 89): drop AES" ++ device, .{ aes, config.trust, config.role });
    }
    if (config.widemul) |widemul| {
        std.process.fatal("WIDEMUL={t} chooses a device object's multiply, and TRUST={t} ROLE={t} " ++ builds ++
            "holds both multiplies and picks one per session from ch_cfg.cpu " ++
            "(docs/decisions.md 89): drop WIDEMUL" ++ device, .{ widemul, config.trust, config.role });
    }
}

/// The host test, as the Makefile's HOST_TARGET runs it on cc
/// (docs/decisions.md 89): the target is arm64 or x86-64, and it has NEON or
/// SSE2 on a little-endian core. Zig names a big-endian arm64 target
/// aarch64_be, which is neither architecture here. The Makefile's third
/// probe, unsigned __int128, asks nothing more of either architecture:
/// clang, which compiles every source here, defines __SIZEOF_INT128__ for
/// both under every ABI, x32 and ILP32 included.
fn hostTarget(target: std.Target) bool {
    return switch (target.cpu.arch) {
        .aarch64 => target.cpu.has(.aarch64, .neon),
        .x86_64 => target.cpu.has(.x86, .sse2),
        else => false,
    };
}

/// Whether config builds a host object for target (docs/decisions.md 89):
/// TRUST=webpki, ROLE=server and ROLE=both where the host test passed. The
/// test's result is HOST_TARGET's where a check set it, as the Makefile
/// takes its own, and hostTarget's answer for the target everywhere else.
fn hostObject(config: Config, target: std.Target) bool {
    const passed = if (config.host_target) |text| text.len != 0 else hostTarget(target);
    return passed and !deviceClient(config);
}

/// A raw or ca client: the one build whose key exchange KEX chooses, and
/// the one product that builds the portable object on a host target.
fn deviceClient(config: Config) bool {
    return config.role == .client and switch (config.trust) {
        .@"raw-rsa", .@"raw-ecdsa", .@"ca-rsa", .@"ca-ecdsa" => true,
        .webpki, .none => false,
    };
}

/// LIB_DEF, LIB_SRCS and PUBLIC, assembled from the axis blocks as the
/// Makefile assembles them, for an object compiled for target.
fn computePlan(b: *std.Build, config: Config, target: std.Target) Plan {
    // A host object (docs/decisions.md 89): TRUST=webpki, ROLE=server and
    // ROLE=both on a target that passes the host test. A raw or ca client
    // builds the portable object on every target.
    const host = hostObject(config, target);
    const aes = config.aes orelse .soft;
    // AES_ADD: a host object holds the AES instructions, and a QUIC one the
    // table beside them for the public keys of a session whose caller did
    // not set CH_CPU_CONSTANT_TIME_AES (aes.h); a device object holds the
    // one implementation AES names.
    const aes_impl: Names = if (host) &aes_hw_srcs else switch (aes) {
        .soft => &.{"quic_aes_soft.c"},
        .@"extern" => &.{"aes_extern.c"},
    };
    const aes_quic_impl: Names = if (host) concat(b, &.{ aes_impl, &.{"quic_aes_soft.c"} }) else aes_impl;
    const suite_add: Names = if (config.suite == .aesgcm)
        concat(b, &.{ &.{"aes.c"}, aes_impl, &.{ "gcm.c", "sha512.c", "sha512_compress.c" } })
    else
        &.{};
    const trust = trustAxis(b, config.trust);
    var transport = transportAxis(b, config.transport, aes_quic_impl);
    const role = roleAxis(b, config, &transport);
    // ROLE=both keeps both verifiers, whatever the client half pins.
    const pin_filter: Names = if (config.role == .both) &.{} else pinFilter(config.trust);

    var defs = concat(b, &.{ pinDefs(config.trust), trust.defs, transport.defs, if (host) &.{} else aesDefs(aes), if (config.suite == .aesgcm) &.{"-DCH_SUITE_AES_GCM"} else &.{}, role.defs });
    var lib_srcs = concat(b, &.{
        without(b, &srcs, concat(b, &.{ pin_filter, trust.filter, transport.filter, role.filter })),
        trust.add,
        transport.add,
        without(b, role.add, trust.add),
        without(b, suite_add, concat(b, &.{ trust.add, transport.add, role.add })),
    });

    if (config.kex == .pq) defs = concat(b, &.{ defs, &.{"-DCH_KEX_PQ"} });
    if (config.kex == .pq or config.trust == .webpki or config.role != .client) lib_srcs = concat(b, &.{ lib_srcs, &kex_hybrid_srcs });
    // CPU_RUNTIME_DEF: the host object, which each session's ch_cfg.cpu
    // describes the CPU to.
    if (host) defs = concat(b, &.{ defs, &.{"-DCH_CPU_RUNTIME"} });
    // The wide X25519 field, which a session's
    // CH_CPU_CONSTANT_TIME_MULTIPLY bit picks (docs/decisions.md 52 and 89).
    if (host) lib_srcs = concat(b, &.{ lib_srcs, &.{"x25519_wide.c"} });
    // The wide P-256 files, which the same bit picks, in an object that
    // carries the curve (docs/decisions.md 94).
    if (host and contains(lib_srcs, "p256_point.c")) lib_srcs = concat(b, &.{ lib_srcs, &p256_wide_srcs });
    // P-384's 64-bit field, points and verifier, which p384.c calls in a
    // host object, in every session (docs/decisions.md 97).
    if (host and contains(lib_srcs, "p384.c")) lib_srcs = concat(b, &.{ lib_srcs, &p384_wide_srcs });
    // RSA_MONT64_SRCS: the 64-bit Montgomery arithmetic rsa_mont.c calls
    // in a host object, for the public operation of both RSA verifiers in
    // every session (docs/decisions.md 95).
    if (host and contains(lib_srcs, "rsa_mont.c")) lib_srcs = concat(b, &.{ lib_srcs, &.{"rsa_mont64.c"} });
    // RSA_SIGN64_SRCS: the signer on those limbs, which a session's
    // CH_CPU_CONSTANT_TIME_MULTIPLY bit picks over rsa_sign.c's ladder
    // (docs/decisions.md 95).
    if (host and contains(lib_srcs, "rsa_sign.c")) lib_srcs = concat(b, &.{ lib_srcs, &.{"rsa_sign64.c"} });
    // The vector NTT every session of a host object runs in place of
    // mlkem_poly.c's loops, in an object that carries ML-KEM
    // (docs/decisions.md 101).
    if (host and contains(lib_srcs, "mlkem.c")) lib_srcs = concat(b, &.{ lib_srcs, &.{"mlkem_vector.c"} });
    // The four-way Keccak and ML-KEM's copy over it, which a session's
    // CH_CPU_AVX2 bit picks on x86-64, in an object that carries ML-KEM. On
    // arm64 both hold nothing (docs/decisions.md 107).
    if (host and contains(lib_srcs, "mlkem.c")) lib_srcs = concat(b, &.{ lib_srcs, &.{ "keccak_avx2.c", "mlkem_avx2.c" } });
    // CHACHA_VECTOR_SRCS: the vector ChaCha20 every session of a host
    // object runs, and the AVX2 kernel a session's CH_CPU_AVX2 bit picks
    // on x86-64 (docs/decisions.md 82, 89 and 90).
    if (host) lib_srcs = concat(b, &.{ lib_srcs, &.{ "chacha20_vector.c", "chacha20_avx2.c" } });
    if (config.exporter == .on) defs = concat(b, &.{ defs, &.{ "-DCH_EXPORTER", "-DHKDF_LABEL_MAX=32" } });
    if (config.keylog == .on) defs = concat(b, &.{ defs, &.{"-DCH_KEYLOG"} });
    const widemul = config.widemul orelse .decomposed;
    if (widemul == .native) defs = concat(b, &.{ defs, &.{"-DCH_NATIVE_WIDEMUL"} });
    // A host object holds both multiplies, and each session's
    // CH_CPU_CONSTANT_TIME_MULTIPLY bit picks one: the native copy of every
    // copied file the object carries (docs/decisions.md 87 and 89).
    if (host) lib_srcs = concat(b, &.{ lib_srcs, nativeCopies(b, lib_srcs) });
    // The vector Poly1305 multiplies, so a host object holds it as the
    // native copy the multiply bit picks, and a device object holds none
    // (docs/decisions.md 83 and 89).
    if (host) lib_srcs = concat(b, &.{ lib_srcs, &.{"poly1305_vector_native.c"} });
    // hash_hw_of: SHA-256 on the CPU's SHA-256 instructions beside
    // sha256.c, and hkdf.c and keysched.c compiled once more over it, which
    // a session's CH_CPU_CONSTANT_TIME_SHA256 bit picks. With SUITE=aesgcm,
    // whose key schedule and transcript run SHA-384 under a session's
    // value, SHA-512 on arm64's SHA-512 instructions stands beside
    // sha512.c too (docs/decisions.md 93).
    if (host) lib_srcs = concat(b, &.{ lib_srcs, hashHwSources(b, lib_srcs, config.suite == .aesgcm) });
    if (config.tx_record) |text| defs = concat(b, &.{ defs, &.{b.fmt("-DCH_TX_PT={s}", .{text})} });
    if (config.rand == .drbg) {
        defs = concat(b, &.{ defs, &.{"-DCH_RAND_DRBG"} });
        lib_srcs = concat(b, &.{ lib_srcs, &.{"drbg.c"} });
    }
    if (config.rand == .@"extern") defs = concat(b, &.{ defs, &.{"-DCH_RAND_EXTERN"} });
    // Each session names its own source in ch_cfg, so the object packages
    // no generator, exports nothing more and imports no ch_rand_bytes.
    if (config.rand == .session) defs = concat(b, &.{ defs, &.{"-DCH_RAND_SESSION"} });

    // The hardware statement, which the Makefile takes in CFLAGS.
    if (config.aes_extern_constant_time) defs = concat(b, &.{ defs, &.{"-DCH_AES_EXTERN_CONSTANT_TIME"} });

    const public_rand: Names = if (config.rand == .drbg) &.{ "ch_drbg_seed", "ch_rand_bytes" } else &.{};
    const public_export: Names = if (config.exporter == .on) &.{"ch_export"} else &.{};
    const public_ca: Names = if (trustsCa(config.trust)) &.{"ch_pubkey_from_pem"} else &.{};
    const names = concat(b, &.{ role.public, public_rand, public_ca, public_export, &.{"ch_build"} });

    // The hooks the object imports, which the image defines
    // (docs/porting.md) and lib-check admits as undefined. An AES=extern
    // device object imports ch_aes_block where it compiles AES: under QUIC,
    // and under SUITE=aesgcm.
    const compiles_aes = config.transport == .@"quic-nonblocking" or config.suite == .aesgcm;
    const hooks = concat(b, &.{
        &.{"ch_assert_fail"},
        if (config.rand == .@"extern") &.{"ch_rand_bytes"} else &.{},
        if (config.keylog == .on) &.{"ch_keylog"} else &.{},
        if (!host and aes == .@"extern" and compiles_aes) &.{"ch_aes_block"} else &.{},
    });
    return .{
        .srcs = lib_srcs,
        .defs = defs,
        .public = symbolNames(b, config.transport, names),
        .headers = headersDeclaring(b, concat(b, &.{ names, hooks })),
    };
}

/// The header of each declaration that declares one of names, in the
/// order of declarations. A name no header there declares stops the
/// build, so a new export cannot leave the module without its header.
fn headersDeclaring(b: *std.Build, names: Names) Names {
    for (names) |name| {
        for (declarations) |declaration| {
            if (contains(declaration.names, name)) break;
        } else std.process.fatal("build.zig's declarations name no header that declares {s}", .{name});
    }
    var out = std.ArrayList([]const u8).initCapacity(b.allocator, declarations.len) catch @panic("OOM");
    for (declarations) |declaration| {
        for (declaration.names) |declared| {
            if (contains(names, declared)) {
                out.appendAssumeCapacity(declaration.header);
                break;
            }
        }
    }
    return out.items;
}

fn trustsCa(trust: Trust) bool {
    return trust == .@"ca-rsa" or trust == .@"ca-ecdsa";
}

/// PIN_DEF: the ecdsa half of a pinned trust value.
fn pinDefs(trust: Trust) Names {
    return if (trust == .@"raw-ecdsa" or trust == .@"ca-ecdsa") &.{"-DCH_PIN_ECDSA"} else &.{};
}

/// PIN_FILTER: the verifier a pinned trust value does not name.
fn pinFilter(trust: Trust) Names {
    return switch (trust) {
        .@"raw-rsa", .@"ca-rsa" => &.{"p256.c"},
        .@"raw-ecdsa", .@"ca-ecdsa" => &.{ "rsa.c", "rsa_mont.c" },
        .webpki, .none => &.{},
    };
}

fn aesDefs(aes: Aes) Names {
    return switch (aes) {
        .soft => &.{},
        .@"extern" => &.{"-DCH_AES_EXTERN"},
    };
}

/// TRUST_DEF, TRUST_FILTER and TRUST_ADD.
fn trustAxis(b: *std.Build, trust: Trust) Axis {
    return switch (trust) {
        .@"raw-rsa", .@"raw-ecdsa", .none => .{ .filter = &(certificate_srcs ++ webpki_srcs) },
        .@"ca-rsa", .@"ca-ecdsa" => .{ .defs = &.{"-DCH_TRUST_CA"}, .filter = &webpki_srcs },
        .webpki => .{
            .defs = &.{"-DCH_TRUST_WEBPKI"},
            .filter = &.{ "pem.c", "x509.c", "x509_ca.c" },
            .add = concat(b, &.{ &webpki_chain_srcs, without(b, &webpki_srcs, &srcs), &webpki_kex_srcs }),
        },
    };
}

/// TRANSPORT_DEF, TRANSPORT_FILTER, TRANSPORT_ADD and PUBLIC_TRANSPORT.
fn transportAxis(b: *std.Build, transport: Transport, aes_impl: Names) Axis {
    return switch (transport) {
        .@"quic-nonblocking" => .{
            .defs = &.{"-DCH_TRANSPORT_QUIC_NONBLOCKING"},
            .filter = &quic_replaced,
            .add = concat(b, &.{ &.{"aes.c"}, aes_impl, &quic_srcs_after_aes }),
            .public = &(public_quic ++ public_ticket ++ public_alert),
        },
        .@"tcp-nonblocking" => .{
            .defs = &.{"-DCH_TRANSPORT_TCP_NONBLOCKING"},
            .filter = &.{"handshake.c"},
            .add = &.{ "tcp_nonblocking.c", "tcp_nonblocking_frame.c", "tcp_nonblocking_step.c" },
            .public = &public_tcp_nonblocking,
        },
        .@"tcp-blocking" => .{ .public = &public_tcp_blocking },
    };
}

/// ROLE_DEF, ROLE_FILTER, ROLE_ADD and PUBLIC_ROLE. A server role swaps
/// the server's driver for the transport's, and ROLE=server also drops the
/// client's step table from the transport's add, as the Makefile rewrites
/// TRANSPORT_ADD in that arm.
fn roleAxis(b: *std.Build, config: Config, transport: *Axis) Axis {
    if (config.role == .client) return .{ .public = transport.public };
    const server_only = config.role == .server;
    var role = Axis{
        .defs = if (server_only) &.{"-DCH_ROLE_SERVER"} else &.{ "-DCH_ROLE_SERVER", "-DCH_ROLE_BOTH" },
        .filter = if (server_only) &client_replaced else &.{},
    };
    const driver_swapped = without(b, &server_add, &.{"srv_handshake.c"});
    switch (config.transport) {
        .@"quic-nonblocking" => {
            role.add = concat(b, &.{ driver_swapped, &.{ "srv_quic.c", "quic_token.c" } });
            if (server_only) transport.add = without(b, transport.add, &.{"quic_step.c"});
            role.public = if (server_only)
                concat(b, &.{ &public_srv_quic, &public_quic_either_role })
            else
                concat(b, &.{ transport.public, &public_srv_quic });
        },
        .@"tcp-nonblocking" => {
            role.add = concat(b, &.{ driver_swapped, &.{"srv_tcp_nonblocking.c"} });
            if (server_only) transport.add = without(b, transport.add, &.{"tcp_nonblocking_step.c"});
            role.public = if (server_only)
                concat(b, &.{ &public_srv_tcp_nonblocking, &public_record_either_role })
            else
                concat(b, &.{ transport.public, &public_srv_tcp_nonblocking });
        },
        .@"tcp-blocking" => {
            role.add = &server_add;
            role.public = if (server_only)
                concat(b, &.{ &public_srv_tcp_blocking, &public_session })
            else
                concat(b, &.{ transport.public, &public_srv_tcp_blocking });
        },
    }
    return role;
}

/// PUBLIC in the Makefile: each of the six exports that objects of more
/// than one transport carry takes the transport into its symbol name, and
/// the build record's symbol is named for its type (docs/decisions.md 61,
/// 72 and 75).
fn symbolNames(b: *std.Build, transport: Transport, names: Names) Names {
    const suffix = b.dupe(@tagName(transport));
    std.mem.replaceScalar(u8, suffix, '-', '_');
    const out = b.allocator.alloc([]const u8, names.len) catch @panic("OOM");
    for (names, out) |name, *symbol| {
        if (std.mem.eql(u8, name, "ch_build")) {
            symbol.* = b.fmt("ch_build_info_{s}", .{suffix});
        } else if (std.mem.eql(u8, name, "ch_srv_check") or std.mem.eql(u8, name, "ch_pubkey_from_pem") or
            std.mem.eql(u8, name, "ch_ticket_obfuscated_age") or contains(&public_alert, name))
        {
            symbol.* = b.fmt("{s}_{s}", .{ name, suffix });
        } else {
            symbol.* = name;
        }
    }
    return out;
}

/// The lists joined in order.
fn concat(b: *std.Build, lists: []const Names) Names {
    var total: usize = 0;
    for (lists) |list| total += list.len;
    const out = b.allocator.alloc([]const u8, total) catch @panic("OOM");
    var i: usize = 0;
    for (lists) |list| {
        @memcpy(out[i..][0..list.len], list);
        i += list.len;
    }
    return out;
}

/// $(filter-out removed,list): list without every name removed holds.
fn without(b: *std.Build, list: Names, removed: Names) Names {
    var out = std.ArrayList([]const u8).initCapacity(b.allocator, list.len) catch @panic("OOM");
    for (list) |name| {
        if (!contains(removed, name)) out.appendAssumeCapacity(name);
    }
    return out.items;
}

/// $(patsubst %.c,%_native.c,$(filter $(WIDEMUL_COPIED),list)): the
/// native copy of each file of list that widemul_copied names, in list's
/// order.
fn nativeCopies(b: *std.Build, list: Names) Names {
    var out = std.ArrayList([]const u8).initCapacity(b.allocator, list.len) catch @panic("OOM");
    for (list) |name| {
        if (contains(&widemul_copied, name)) {
            out.appendAssumeCapacity(b.fmt("{s}_native.c", .{name[0 .. name.len - 2]}));
        }
    }
    return out.items;
}

/// The Makefile's hash_hw_of as it packages an object: what a host object
/// holds beside the hash files of list, in the Makefile's order. It holds
/// sha512_hw.c only where suite says the object runs SHA-384 under a
/// session's value. Keccak on the SHA-3 instructions and ML-KEM's two copies
/// over it stand beside sha3.c, mlkem.c and mlkem_poly.c the same way.
fn hashHwSources(b: *std.Build, list: Names, suite: bool) Names {
    const pairs = [_][2][]const u8{
        .{ "sha256.c", "sha256_hw.c" },
        .{ "sha512.c", "sha512_hw.c" },
        .{ "hkdf.c", "hkdf_hw.c" },
        .{ "keysched.c", "keysched_hw.c" },
        .{ "sha3.c", "sha3_hw.c" },
        .{ "mlkem.c", "mlkem_hw.c" },
        .{ "mlkem_poly.c", "mlkem_poly_hw.c" },
    };
    var out = std.ArrayList([]const u8).initCapacity(b.allocator, pairs.len) catch @panic("OOM");
    for (pairs) |pair| {
        const is_sha512 = std.mem.eql(u8, pair[0], "sha512.c");
        if (is_sha512 and !suite) continue;
        if (contains(list, pair[0])) out.appendAssumeCapacity(pair[1]);
    }
    return out.items;
}

/// Whether list holds name.
fn contains(list: Names, name: []const u8) bool {
    for (list) |held| {
        if (std.mem.eql(u8, held, name)) return true;
    }
    return false;
}

/// A C header that includes each of headers, one line each.
fn includes(b: *std.Build, headers: Names) []const u8 {
    var text: std.ArrayList(u8) = .empty;
    text.appendSlice(b.allocator, "// Written by build.zig: the public headers of one packaged object.\n") catch @panic("OOM");
    for (headers) |header| text.print(b.allocator, "#include \"{s}\"\n", .{header}) catch @panic("OOM");
    return text.items;
}

/// One name per line, each line ended.
fn lines(b: *std.Build, names: Names) []const u8 {
    return b.fmt("{s}\n", .{std.mem.join(b.allocator, "\n", names) catch @panic("OOM")});
}
