//! The rules tools/localize_symbols.zig applies to either object format:
//! which names stay global, the order the rewritten symbol table takes, and
//! how a refusal is reported.
const std = @import("std");

/// Every refusal returns this error after it writes its message to the
/// Report. The tool then writes no output, so a build never links an
/// object that was rewritten in part.
pub const Refused = error{Refused};

pub const Report = struct {
    arena: std.mem.Allocator,
    message: []const u8 = "",

    pub fn refuse(report: *Report, comptime format: []const u8, arguments: anytype) Refused {
        report.message = std.fmt.allocPrint(report.arena, format, arguments) catch "out of memory while writing the refusal";
        return error.Refused;
    }
};

/// The names that stay global, as C spells them. Mach-O writes a C name
/// with a leading underscore and ELF writes it as it is, so each format
/// gives its prefix. found records which names a defined global matched.
pub const Keep = struct {
    names: []const []const u8,
    prefix: []const u8,
    found: []bool,

    pub fn init(arena: std.mem.Allocator, names: []const []const u8, prefix: []const u8) !Keep {
        const found = try arena.alloc(bool, names.len);
        @memset(found, false);
        return .{ .names = names, .prefix = prefix, .found = found };
    }

    /// Whether symbol, as the object spells it, is one of the names.
    pub fn holds(keep: Keep, symbol: []const u8) ?usize {
        if (!std.mem.startsWith(u8, symbol, keep.prefix)) return null;
        const name = symbol[keep.prefix.len..];
        for (keep.names, 0..) |kept, i| {
            if (std.mem.eql(u8, kept, name)) return i;
        }
        return null;
    }

    /// The first name no defined global matched.
    pub fn missing(keep: Keep) ?[]const u8 {
        for (keep.names, keep.found) |name, found| {
            if (!found) return name;
        }
        return null;
    }
};

/// Where a symbol goes in the rewritten table.
pub const Class = enum {
    /// Local before the rewrite, and left as it was.
    local,
    /// Defined and global before the rewrite, and local after it.
    localized,
    /// Global after the rewrite: a kept name, or an undefined symbol.
    global,
};

/// The new index of each symbol, by its old index. Every local comes
/// first, then every localized symbol, then every global, each group in
/// its old order. Both formats require the locals before the globals, and
/// keeping each group's order keeps any order the input had within it: a
/// Mach-O object's defined globals before its undefined ones.
pub fn order(arena: std.mem.Allocator, classes: []const Class) ![]u32 {
    const new_index = try arena.alloc(u32, classes.len);
    var next: u32 = 0;
    for ([_]Class{ .local, .localized, .global }) |group| {
        for (classes, new_index) |class, *index| {
            if (class != group) continue;
            index.* = next;
            next += 1;
        }
    }
    return new_index;
}

/// How many symbols the rewritten table holds before its first global.
pub fn localCount(classes: []const Class) u32 {
    var count: u32 = 0;
    for (classes) |class| {
        if (class != .global) count += 1;
    }
    return count;
}

/// Writes each entry of the table to the slot its new index names. table
/// holds count entries of entry_size bytes each.
pub fn permute(arena: std.mem.Allocator, table: []u8, entry_size: usize, new_index: []const u32) !void {
    const copy = try arena.dupe(u8, table);
    for (new_index, 0..) |to, from| {
        const source = copy[from * entry_size ..][0..entry_size];
        @memcpy(table[to * entry_size ..][0..entry_size], source);
    }
}

test "order puts the locals first, then the localized symbols, then the globals" {
    const classes = [_]Class{ .local, .global, .localized, .local, .global, .localized };
    const new_index = try order(std.testing.allocator, &classes);
    defer std.testing.allocator.free(new_index);
    try std.testing.expectEqualSlices(u32, &.{ 0, 4, 2, 1, 5, 3 }, new_index);
    try std.testing.expectEqual(@as(u32, 4), localCount(&classes));
}

test "keep matches a name under the format's prefix and nothing else" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const keep = try Keep.init(arena.allocator(), &.{ "ch_read", "ch_write" }, "_");
    try std.testing.expectEqual(@as(?usize, 1), keep.holds("_ch_write"));
    try std.testing.expectEqual(@as(?usize, null), keep.holds("ch_write"));
    try std.testing.expectEqual(@as(?usize, null), keep.holds("_ch_writer"));
    keep.found[1] = true;
    try std.testing.expectEqualStrings("ch_read", keep.missing().?);
}
