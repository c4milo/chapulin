//! A Zig project that depends on chapulin as colibri does, which
//! test/zig-build-check.sh builds against the staged package
//! (docs/decisions.md 70 and 73). Each object is a dependency whose
//! options come from one row of the script's configurations, and each
//! program imports that dependency's module "chapulin", which carries the
//! object. No program adds the object itself.
//!
//! - `zig build -Dobject=ROW -Dexport=NAME... -Dimport=NAME...
//!   -Dconstant=NAME...` installs bin/matches, matches.zig built against
//!   one object, which requires chapulin.c to declare each export, to
//!   declare no ch_ function the object neither exports nor imports, and
//!   to declare and evaluate each constant, and bin/unit, the tests in
//!   unit.zig built against the same object.
//! - Adding `-Dloop` also installs bin/loop, loop.zig built against that
//!   object, which must be ROLE=both: a client and a server of it run
//!   against each other through the API. It reads the r2 chain, its
//!   anchor and the leaf key from webpki_corpus.h, which the script
//!   copies from test/.
//! - `zig build -Dh2=ROW -Dquic=ROW` installs bin/pair, pair.zig built
//!   against colibri's tcp-nonblocking object and its QUIC object in one
//!   image.
//!
//! A row is the options chapulin's build.zig takes, as NAME=VALUE words:
//! "RAND=extern TRANSPORT=quic-nonblocking AES=extern CH_AES_EXTERN_CONSTANT_TIME=true".
const std = @import("std");

/// The options chapulin's build.zig takes. A field no row word names stays
/// null, and the dependency then applies its own default. Every value is
/// the text of the row, which the dependency parses as it parses -D.
const Options = struct {
    target: std.Build.ResolvedTarget,
    TRANSPORT: ?[]const u8 = null,
    ROLE: ?[]const u8 = null,
    TRUST: ?[]const u8 = null,
    SUITE: ?[]const u8 = null,
    AES: ?[]const u8 = null,
    RAND: ?[]const u8 = null,
    KEX: ?[]const u8 = null,
    CHACHA: ?[]const u8 = null,
    WIDEMUL: ?[]const u8 = null,
    EXPORTER: ?[]const u8 = null,
    KEYLOG: ?[]const u8 = null,
    TX_RECORD: ?[]const u8 = null,
    HOST_TARGET: ?[]const u8 = null,
    CH_AES_EXTERN_CONSTANT_TIME: ?[]const u8 = null,
};

/// One dependency a program imports, under the name the program imports
/// it by.
const Import = struct { name: []const u8, dependency: *std.Build.Dependency };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const object = b.option([]const u8, "object", "The options of the object matches.zig, unit.zig and loop.zig link");
    const loop = b.option(bool, "loop", "Also install bin/loop; the object must be ROLE=both") orelse false;
    const h2 = b.option([]const u8, "h2", "The options of the tcp-nonblocking object pair.zig links");
    const quic = b.option([]const u8, "quic", "The options of the QUIC object pair.zig links");
    if (object == null and (h2 == null or quic == null)) {
        std.process.fatal("name -Dobject, or -Dh2 and -Dquic", .{});
    }
    if (object) |row| {
        const chapulin = b.dependency("chapulin", options(target, row));
        const imports = [_]Import{.{ .name = "chapulin", .dependency = chapulin }};
        const exports = b.addOptions();
        exports.addOption([]const []const u8, "names", b.option([]const []const u8, "export", "A name the object exports") orelse &.{});
        exports.addOption([]const []const u8, "imports", b.option([]const []const u8, "import", "A ch_ name the object imports, a hook the image defines") orelse &.{});
        exports.addOption([]const []const u8, "constants", b.option([]const []const u8, "constant", "A length or cap a public header names") orelse &.{});
        const matches = program(b, "matches", target, optimize, &imports);
        matches.addOptions("exports", exports);
        const unit = b.addTest(.{ .name = "unit", .root_module = module(b, "unit", target, optimize, &imports) });
        b.installArtifact(unit);
        if (loop) {
            const corpus = b.addTranslateC(.{ .root_source_file = b.path("webpki_corpus.h"), .target = target, .optimize = optimize });
            program(b, "loop", target, optimize, &imports).addImport("corpus", corpus.createModule());
        }
    }
    if (h2 != null and quic != null) {
        _ = program(b, "pair", target, optimize, &.{
            .{ .name = "chapulin_h2", .dependency = b.dependency("chapulin", options(target, h2.?)) },
            .{ .name = "chapulin_quic", .dependency = b.dependency("chapulin", options(target, quic.?)) },
        });
    }
}

/// The module of NAME.zig, with each dependency's module "chapulin"
/// imported under its name. That module carries the dependency's object,
/// so the program links it with no addObjectFile of its own.
fn module(b: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, imports: []const Import) *std.Build.Module {
    const out = b.createModule(.{
        .root_source_file = b.path(b.fmt("{s}.zig", .{name})),
        .target = target,
        .optimize = optimize,
    });
    for (imports) |import| out.addImport(import.name, import.dependency.module("chapulin"));
    return out;
}

/// Installs NAME.zig as bin/NAME and returns the program's root module.
fn program(b: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, imports: []const Import) *std.Build.Module {
    const root = module(b, name, target, optimize, imports);
    b.installArtifact(b.addExecutable(.{ .name = name, .root_module = root }));
    return root;
}

/// The options one row names.
fn options(target: std.Build.ResolvedTarget, row: []const u8) Options {
    var out = Options{ .target = target };
    var words = std.mem.tokenizeScalar(u8, row, ' ');
    while (words.next()) |word| {
        const equals = std.mem.indexOfScalar(u8, word, '=') orelse std.process.fatal("{s} is not NAME=VALUE", .{word});
        const name = word[0..equals];
        var known = false;
        inline for (@typeInfo(Options).@"struct".fields) |field| {
            if (field.type == ?[]const u8 and std.mem.eql(u8, field.name, name)) {
                @field(out, field.name) = word[equals + 1 ..];
                known = true;
            }
        }
        if (!known) std.process.fatal("{s} is not an option chapulin's build.zig takes", .{name});
    }
    return out;
}
