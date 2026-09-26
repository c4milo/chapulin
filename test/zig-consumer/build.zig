//! A Zig project that depends on chapulin as colibri does, which
//! test/zig-build-check.sh builds against the staged package
//! (docs/decisions.md 70). Each object is a dependency whose options come
//! from one row of the script's configurations, and each program imports
//! that dependency's module "chapulin" and links its object "chapulin.o".
//!
//! - `zig build -Dobject=ROW -Dexport=NAME...` installs bin/matches,
//!   matches.zig built against one object, which requires the module to
//!   declare each NAME.
//! - `zig build -Dh2=ROW -Dquic=ROW` installs bin/pair, pair.zig built
//!   against colibri's tcp-nonblocking object and its QUIC object in one
//!   image.
//!
//! A row is the options chapulin's build.zig takes, as NAME=VALUE words:
//! "RAND=extern TRANSPORT=quic-nonblocking CH_NATIVE_AES=true".
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
    X25519: ?[]const u8 = null,
    WIDEMUL: ?[]const u8 = null,
    EXPORTER: ?[]const u8 = null,
    KEYLOG: ?[]const u8 = null,
    CH_NATIVE_AES: ?[]const u8 = null,
    CH_AES_EXTERN_CONSTANT_TIME: ?[]const u8 = null,
    CH_NATIVE_MUL128: ?[]const u8 = null,
};

/// One dependency a program imports, under the name the program imports
/// it by.
const Import = struct { name: []const u8, dependency: *std.Build.Dependency };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const object = b.option([]const u8, "object", "The options of the object matches.zig links");
    const h2 = b.option([]const u8, "h2", "The options of the tcp-nonblocking object pair.zig links");
    const quic = b.option([]const u8, "quic", "The options of the QUIC object pair.zig links");
    if (object == null and (h2 == null or quic == null)) {
        std.process.fatal("name -Dobject, or -Dh2 and -Dquic", .{});
    }
    if (object) |row| {
        const exports = b.addOptions();
        exports.addOption([]const []const u8, "names", b.option([]const []const u8, "export", "A name the object exports") orelse &.{});
        const matches = program(b, "matches", target, optimize, &.{
            .{ .name = "chapulin", .dependency = b.dependency("chapulin", options(target, row)) },
        });
        matches.addOptions("exports", exports);
    }
    if (h2 != null and quic != null) {
        _ = program(b, "pair", target, optimize, &.{
            .{ .name = "chapulin_h2", .dependency = b.dependency("chapulin", options(target, h2.?)) },
            .{ .name = "chapulin_quic", .dependency = b.dependency("chapulin", options(target, quic.?)) },
        });
    }
}

/// Installs NAME.zig as bin/NAME, with each dependency's module imported
/// under its name and each dependency's object linked, and returns the
/// program's root module.
fn program(b: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, imports: []const Import) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(b.fmt("{s}.zig", .{name})),
        .target = target,
        .optimize = optimize,
    });
    for (imports) |import| {
        module.addImport(import.name, import.dependency.module("chapulin"));
        module.addObjectFile(import.dependency.namedLazyPath("chapulin.o"));
    }
    b.installArtifact(b.addExecutable(.{ .name = name, .root_module = module }));
    return module;
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
