//! A program of the one module of both nonblocking objects
//! (docs/decisions.md 245). It defines no ch_assert_fail. Each half's
//! build record must match its headers, and then the program calls the
//! hook, which the module defines: the program must stop with the
//! module's panic, which test/zig-build-check.sh reads.
const std = @import("std");
const chapulin = @import("chapulin");

pub fn main() u8 {
    if (!chapulin.tcp.build_matches()) return 1;
    if (!chapulin.quic.build_matches()) return 2;
    chapulin.tcp.c.ch_assert_fail("both", "both.zig", 1);
}
