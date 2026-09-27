//! A client and a server of one ROLE=both object against each other,
//! through the module's API alone: loop_record.zig for a tcp-nonblocking
//! object and loop_quic.zig for a QUIC one. It exits 0 when every step
//! did what the API says, and 1 at the first that did not.
const std = @import("std");
const chapulin = @import("chapulin");
const hooks = @import("hooks.zig");
const c = chapulin.c;

comptime {
    hooks.define(&.{c});
}

const loop = if (@hasDecl(c, "ch_srv_record_init"))
    @import("loop_record.zig")
else if (@hasDecl(c, "ch_srv_quic_init"))
    @import("loop_quic.zig")
else
    @compileError("loop.zig needs a ROLE=both object");

/// An error from here exits 1, and the Debug build prints its return
/// trace, which names the step that failed.
pub fn main() !void {
    if (!chapulin.buildMatches()) return error.BuildRecordDiffers;
    try loop.run();
}
