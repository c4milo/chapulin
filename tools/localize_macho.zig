//! The Mach-O half of tools/localize_symbols.zig: what `nmedit -s` does to
//! a 64-bit little-endian relocatable object (MH_OBJECT).
//!
//! Every defined external symbol whose name is not kept stops being
//! external: its N_EXT and N_PEXT bits are cleared. LC_DYSYMTAB splits the
//! symbol table into three ranges, locals, then defined externals, then
//! undefined externals, so the table is reordered (localize_rules.zig) and
//! the ranges rewritten. Two structures hold symbol indices, and each is
//! renumbered to the new order: the r_symbolnum of every relocation whose
//! r_extern bit is set, and every entry of the indirect symbol table. As
//! nmedit does, the tool also turns the debugging entry of each localized
//! global variable into one that carries its address (convertStabs).
//!
//! No byte moves but the symbol table's own entries and the indices, so
//! every section keeps its offset and size.
const std = @import("std");
const rules = @import("localize_rules.zig");

pub const magic_64 = 0xfeedfacf;
const mh_object = 1;

const lc_segment = 0x1;
const lc_symtab = 0x2;
const lc_dysymtab = 0xb;
const lc_segment_64 = 0x19;
/// The load commands the tool knows hold no symbol index: the build and
/// minimum-version records, data-in-code, the linker options and the
/// optimization hints.
const lc_no_symbols = [_]u32{ 0x24, 0x25, 0x29, 0x2d, 0x2e, 0x2f, 0x30, 0x32 };

const n_stab = 0xe0;
const n_gsym = 0x20;
const n_stsym = 0x26;
const n_pext = 0x10;
const n_type = 0x0e;
const n_ext = 0x01;
const n_undf = 0x0;
const n_abs = 0x2;
const n_sect = 0xe;

const indirect_symbol_local = 0x80000000;
const indirect_symbol_abs = 0x40000000;

const nlist_size = 16;
const section_size = 80;
const relocation_size = 8;
const r_scattered = 0x80000000;
const r_extern_bit = 1 << 27;
const r_symbolnum_mask = 0x00ff_ffff;

fn read(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn write(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

/// A table the file holds, checked to lie inside the file.
const Table = struct {
    offset: usize,
    count: usize,
};

const Commands = struct {
    /// Where the LC_SYMTAB and LC_DYSYMTAB commands start.
    symtab: usize,
    dysymtab: usize,
    /// Every section's relocation table.
    relocations: []const Table,
};

pub fn localize(arena: std.mem.Allocator, bytes: []u8, names: []const []const u8, report: *rules.Report) !void {
    if (bytes.len < 32) return report.refuse("the file is {d} bytes, too short for a Mach-O header", .{bytes.len});
    if (read(bytes, 12) != mh_object) return report.refuse("filetype is {d}; only a relocatable object (MH_OBJECT) is rewritten", .{read(bytes, 12)});
    const commands = try readCommands(arena, bytes, report);

    const symbols = try checkedTable(bytes, read(bytes, commands.symtab + 8), read(bytes, commands.symtab + 12), nlist_size, report);
    const string_offset = read(bytes, commands.symtab + 16);
    const string_size = read(bytes, commands.symtab + 20);
    if (string_offset > bytes.len or string_size > bytes.len - string_offset) return report.refuse("the string table runs past the end of the file", .{});
    const strings = bytes[string_offset..][0..string_size];
    try checkDynamicTable(bytes, commands.dysymtab, symbols.count, report);

    var keep = try rules.Keep.init(arena, names, "_");
    const classes = try arena.alloc(rules.Class, symbols.count);
    const first_defined = read(bytes, commands.dysymtab + 16);
    const first_undefined = read(bytes, commands.dysymtab + 24);
    for (classes, 0..) |*class, i| {
        const entry = bytes[symbols.offset + i * nlist_size ..][0..nlist_size];
        const range: Range = if (i < first_defined) .local else if (i < first_undefined) .defined else .undefined;
        class.* = try classify(entry, strings, i, range, &keep, report);
    }
    if (keep.missing()) |name| return report.refuse("{s} is to stay global, and the object defines no external symbol _{s}", .{ name, name });

    const new_index = try rules.order(arena, classes);
    const symbol_table = bytes[symbols.offset..][0 .. symbols.count * nlist_size];
    try convertStabs(arena, symbol_table, strings, classes, report);
    for (classes, 0..) |class, i| {
        if (class == .localized) symbol_table[i * nlist_size + 4] &= ~@as(u8, n_ext | n_pext);
    }
    try rules.permute(arena, symbol_table, nlist_size, new_index);

    // The ranges: the locals grow by the localized symbols, the defined
    // externals shrink by as many, and the undefined range stays.
    const local_count = rules.localCount(classes);
    write(bytes, commands.dysymtab + 12, local_count);
    write(bytes, commands.dysymtab + 16, local_count);
    write(bytes, commands.dysymtab + 20, first_undefined - local_count);

    for (commands.relocations) |relocations| try renumberRelocations(bytes, relocations, new_index, report);
    const indirect = try checkedTable(bytes, read(bytes, commands.dysymtab + 56), read(bytes, commands.dysymtab + 60), 4, report);
    for (0..indirect.count) |i| {
        const offset = indirect.offset + i * 4;
        const entry = read(bytes, offset);
        if (entry & (indirect_symbol_local | indirect_symbol_abs) != 0) continue;
        write(bytes, offset, try lookUp(new_index, entry, report));
    }
}

fn checkedTable(bytes: []const u8, offset: u32, count: u32, entry_size: usize, report: *rules.Report) !Table {
    if (offset > bytes.len or count > (bytes.len - offset) / entry_size) return report.refuse("a table of {d} entries at {d} runs past the end of the file", .{ count, offset });
    return .{ .offset = offset, .count = count };
}

fn readCommands(arena: std.mem.Allocator, bytes: []const u8, report: *rules.Report) !Commands {
    const count = read(bytes, 16);
    const size = read(bytes, 20);
    if (size > bytes.len - 32) return report.refuse("the load commands run past the end of the file", .{});
    var symtab: ?usize = null;
    var dysymtab: ?usize = null;
    var relocations: std.ArrayList(Table) = .empty;
    var offset: usize = 32;
    for (0..count) |_| {
        if (offset + 8 > 32 + size) return report.refuse("a load command runs past sizeofcmds", .{});
        const command = read(bytes, offset);
        const command_size = read(bytes, offset + 4);
        if (command_size < 8 or command_size > 32 + size - offset) return report.refuse("load command 0x{x} has size {d}", .{ command, command_size });
        switch (command) {
            lc_symtab => {
                if (command_size < 24) return report.refuse("LC_SYMTAB is {d} bytes, and Mach-O's is 24", .{command_size});
                symtab = offset;
            },
            lc_dysymtab => {
                if (command_size < 80) return report.refuse("LC_DYSYMTAB is {d} bytes, and Mach-O's is 80", .{command_size});
                dysymtab = offset;
            },
            lc_segment_64 => try readSections(arena, bytes, offset, command_size, &relocations, report),
            lc_segment => return report.refuse("the object has a 32-bit segment; the tool reads 64-bit Mach-O only", .{}),
            else => if (std.mem.indexOfScalar(u32, &lc_no_symbols, command) == null) {
                return report.refuse("load command 0x{x} is one the tool does not know, and it may hold symbol indices", .{command});
            },
        }
        offset += command_size;
    }
    return .{
        .symtab = symtab orelse return report.refuse("the object has no LC_SYMTAB", .{}),
        .dysymtab = dysymtab orelse return report.refuse("the object has no LC_DYSYMTAB, so its symbol ranges are unknown", .{}),
        .relocations = relocations.items,
    };
}

fn readSections(arena: std.mem.Allocator, bytes: []const u8, command: usize, command_size: u32, relocations: *std.ArrayList(Table), report: *rules.Report) !void {
    if (command_size < 72) return report.refuse("LC_SEGMENT_64 is {d} bytes, shorter than its 72-byte header", .{command_size});
    const count = read(bytes, command + 64);
    if (72 + @as(u64, count) * section_size > command_size) return report.refuse("a segment's sections run past its load command", .{});
    for (0..count) |i| {
        const section = command + 72 + i * section_size;
        try relocations.append(arena, try checkedTable(bytes, read(bytes, section + 56), read(bytes, section + 60), relocation_size, report));
    }
}

/// The dylib and executable tables LC_DYSYMTAB can name are empty in an
/// object, and the three symbol ranges must cover the table in order.
fn checkDynamicTable(bytes: []const u8, dysymtab: usize, count: usize, report: *rules.Report) !void {
    const first_local = read(bytes, dysymtab + 8);
    const local_count = read(bytes, dysymtab + 12);
    const first_defined = read(bytes, dysymtab + 16);
    const defined_count = read(bytes, dysymtab + 20);
    const first_undefined = read(bytes, dysymtab + 24);
    const undefined_count = read(bytes, dysymtab + 28);
    if (first_local != 0 or first_defined != local_count or first_undefined != @as(u64, first_defined) + defined_count or
        @as(u64, first_undefined) + undefined_count != count)
    {
        return report.refuse("LC_DYSYMTAB's ranges do not cover the {d} symbols in order", .{count});
    }
    // ntoc, nmodtab, nextrefsyms, nextrel and nlocrel.
    for ([_]usize{ 36, 44, 52, 68, 76 }) |field| {
        if (read(bytes, dysymtab + field) != 0) return report.refuse("LC_DYSYMTAB names a table an object does not carry (field at {d})", .{field});
    }
}

const Range = enum { local, defined, undefined };

/// Where symbol i goes, and whether its name is kept. Each symbol must
/// belong to the LC_DYSYMTAB range it sits in; a table that breaks that
/// is refused rather than guessed at.
fn classify(entry: []const u8, strings: []const u8, i: usize, range: Range, keep: *rules.Keep, report: *rules.Report) !rules.Class {
    const type_bits = entry[4];
    const external = type_bits & n_stab == 0 and type_bits & n_ext != 0;
    if (!external) {
        if (range != .local) return report.refuse("symbol {d} is not external and sits outside the local range", .{i});
        return .local;
    }
    const kind = type_bits & n_type;
    const value = std.mem.readInt(u64, entry[8..16], .little);
    if (kind == n_undf and value == 0) {
        if (range != .undefined) return report.refuse("symbol {d} is undefined and sits outside the undefined range", .{i});
        return .global;
    }
    if (range != .defined) return report.refuse("symbol {d} is defined and external and sits outside the defined range", .{i});
    const name = try symbolName(entry, strings, report);
    const kept = keep.holds(name);
    if (kept) |k| keep.found[k] = true;
    if (kind != n_sect and kind != n_abs) {
        if (kept != null) return .global;
        return report.refuse("{s} is a common or indirect symbol (n_type 0x{x}), which cannot be made local", .{ name, type_bits });
    }
    return if (kept != null) .global else .localized;
}

/// The other change nmedit makes. A debugger finds a global variable's
/// address from its N_GSYM debugging entry by looking the name up among
/// the external symbols, which a localized name no longer is. So each
/// N_GSYM entry that names a localized symbol becomes an N_STSYM entry,
/// which carries the symbol's section and address itself. An object built
/// without debugging information has no such entry.
fn convertStabs(arena: std.mem.Allocator, table: []u8, strings: []const u8, classes: []const rules.Class, report: *rules.Report) !void {
    var localized = std.StringHashMap(usize).init(arena);
    for (classes, 0..) |class, i| {
        if (class != .localized) continue;
        try localized.put(try symbolName(table[i * nlist_size ..][0..nlist_size], strings, report), i);
    }
    for (0..classes.len) |i| {
        const entry = table[i * nlist_size ..][0..nlist_size];
        if (entry[4] != n_gsym) continue;
        const symbol = localized.get(try symbolName(entry, strings, report)) orelse continue;
        const source = table[symbol * nlist_size ..][0..nlist_size];
        entry[4] = n_stsym;
        entry[5] = source[5];
        @memcpy(entry[8..16], source[8..16]);
    }
}

fn symbolName(entry: []const u8, strings: []const u8, report: *rules.Report) ![]const u8 {
    const start = read(entry, 0);
    if (start >= strings.len) return report.refuse("a symbol's name starts at {d}, past the string table", .{start});
    const end = std.mem.indexOfScalarPos(u8, strings, start, 0) orelse return report.refuse("a symbol's name runs past the string table", .{});
    return strings[start..end];
}

/// An r_extern relocation names a symbol in r_symbolnum; any other names a
/// section, or on arm64 carries an addend, and keeps its value.
fn renumberRelocations(bytes: []u8, relocations: Table, new_index: []const u32, report: *rules.Report) !void {
    for (0..relocations.count) |i| {
        const offset = relocations.offset + i * relocation_size;
        if (read(bytes, offset) & r_scattered != 0) return report.refuse("a scattered relocation, which 64-bit Mach-O does not use", .{});
        const info = read(bytes, offset + 4);
        if (info & r_extern_bit == 0) continue;
        const symbol = try lookUp(new_index, info & r_symbolnum_mask, report);
        write(bytes, offset + 4, (info & ~@as(u32, r_symbolnum_mask)) | symbol);
    }
}

fn lookUp(new_index: []const u32, old: u32, report: *rules.Report) !u32 {
    if (old >= new_index.len) return report.refuse("an index names symbol {d}, and the table holds {d}", .{ old, new_index.len });
    return new_index[old];
}
