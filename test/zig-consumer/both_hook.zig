//! A program of the one module of both nonblocking objects that reports
//! a failed assertion its own way (docs/decisions.md 245). The module's
//! hook must call chapulinAssertFail below, which prints the line
//! test/zig-build-check.sh reads and exits 0.
const std = @import("std");
const chapulin = @import("chapulin");

pub fn chapulinAssertFail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) noreturn {
    std.debug.print("both_hook: the program's hook ran: {s} ({s}:{d})\n", .{ condition, file, line });
    std.process.exit(0);
}

pub fn main() u8 {
    chapulin.quic.c.ch_assert_fail("both_hook", "both_hook.zig", 2);
}
