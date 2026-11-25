//! The module of a TRANSPORT=nonblocking request (docs/decisions.md 245): chapulin's Zig API over
//! two objects of one configuration, the tcp-nonblocking one as `tcp` and the quic-nonblocking one
//! as `quic`. Each is the module a request of that transport alone gives, so docs/zig.md describes
//! each one: `chapulin.tcp.tcp.Client` is a record session, and `chapulin.quic.quic.Client` a QUIC
//! session.
//!
//! A program imports this module once, so it is the one place that defines ch_assert_fail, the
//! hook every chapulin object imports. Its definition stops the program with the failed
//! condition. A program that reports a failed assertion its own way declares
//! `pub fn chapulinAssertFail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) noreturn`
//! in its root file, and the hook calls that function instead.
const std = @import("std");
const root = @import("root");

/// The tcp-nonblocking object's API.
pub const tcp = @import("chapulin_tcp_object");
/// The quic-nonblocking object's API.
pub const quic = @import("chapulin_quic_object");

/// ch_assert_fail (ch_assert.h): the program's chapulinAssertFail when its root file declares one,
/// and otherwise a panic that names the condition, the file and the line.
fn assertFail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    if (@hasDecl(root, "chapulinAssertFail")) root.chapulinAssertFail(condition, file, line);
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assertFail, .{ .name = "ch_assert_fail" });
}
