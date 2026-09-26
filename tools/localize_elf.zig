//! The ELF half of tools/localize_symbols.zig: what `objcopy -G` does to a
//! relocatable object, for ELF32 and ELF64 in either byte order.
//!
//! Every defined global, weak or unique symbol whose name is not kept
//! becomes STB_LOCAL. ELF requires every local symbol before the first
//! global one, and the symbol table's sh_info holds the index of that first
//! global, so the table is reordered (localize_rules.zig) and sh_info
//! rewritten. Four structures hold symbol indices, and each is renumbered
//! to the new order: the r_info of every SHT_REL and SHT_RELA entry, the
//! sh_info of every SHT_GROUP section, and the parallel SHT_SYMTAB_SHNDX
//! table. SHT_LLVM_ADDRSIG holds indices too, and the tool marks it stale
//! the way `ld -r` does rather than rewrite it (renumber below).
//!
//! No byte moves but the symbol table's own entries and the indices, so
//! every section keeps its offset and size.
//!
//! One kind of object is refused although objcopy rewrites it: MIPS code
//! compiled as position-independent, whose GOT relocations mean something
//! else once their symbol is local (Rewrite.checkMips).
const std = @import("std");
const rules = @import("localize_rules.zig");

const sht_symtab = 2;
const sht_rela = 4;
const sht_rel = 9;
const sht_dynsym = 11;
const sht_group = 17;
const sht_symtab_shndx = 18;
const sht_llvm_addrsig = 0x6fff4c03;

const shn_undef = 0;
const shn_loreserve = 0xff00;
const shn_abs = 0xfff1;
const shn_xindex = 0xffff;

const stb_local = 0;
const stb_global = 1;
const stb_weak = 2;
const stb_gnu_unique = 10;

const sht_strtab = 3;

const et_rel = 1;
const em_mips = 8;

// The MIPS relocation types whose meaning depends on the symbol's binding
// (Rewrite.checkMips).
const r_mips_got16 = 9;
const r_mips_call16 = 11;
const r_mips_got_hi16 = 22;
const r_mips_got_lo16 = 23;
const r_mips_call_hi16 = 30;
const r_mips_call_lo16 = 31;

/// The field offsets and sizes of one ELF class, its byte order, and
/// whether the machine is MIPS.
const Layout = struct {
    endian: std.builtin.Endian,
    elf64: bool,
    mips: bool,

    fn read(layout: Layout, comptime T: type, bytes: []const u8, offset: usize) T {
        return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], layout.endian);
    }

    fn write(layout: Layout, comptime T: type, bytes: []u8, offset: usize, value: T) void {
        std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, layout.endian);
    }

    /// An address-sized field: four bytes in ELF32, eight in ELF64.
    fn readWord(layout: Layout, bytes: []const u8, offset: usize) u64 {
        return if (layout.elf64) layout.read(u64, bytes, offset) else layout.read(u32, bytes, offset);
    }

    fn sectionHeaderSize(layout: Layout) usize {
        return if (layout.elf64) 64 else 40;
    }

    fn symbolSize(layout: Layout) usize {
        return if (layout.elf64) 24 else 16;
    }

    /// st_info and st_shndx sit at different offsets in the two classes.
    fn symbolInfoOffset(layout: Layout) usize {
        return if (layout.elf64) 4 else 12;
    }

    fn symbolIndexOffset(layout: Layout) usize {
        return if (layout.elf64) 6 else 14;
    }
};

const Section = struct {
    /// Where the section header sits in the file.
    header: usize,
    type: u32,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
    entsize: usize,
};

pub fn localize(arena: std.mem.Allocator, bytes: []u8, names: []const []const u8, report: *rules.Report) !void {
    const layout = try readLayout(bytes, report);
    const sections = try readSections(arena, layout, bytes, report);
    const symtab_index = try findSymbolTable(sections, report);
    const symtab = sections[symtab_index];
    const symbol_size = layout.symbolSize();
    if (symtab.entsize != symbol_size or symtab.size % symbol_size != 0) {
        return report.refuse("the symbol table's entry size is {d}, and ELF's is {d}", .{ symtab.entsize, symbol_size });
    }
    if (symtab.link >= sections.len or sections[symtab.link].type != sht_strtab) {
        return report.refuse("the symbol table names section {d} as its string table, which is not one", .{symtab.link});
    }
    const strtab = sections[symtab.link];
    const strings = bytes[strtab.offset..][0..strtab.size];

    var keep = try rules.Keep.init(arena, names, "");
    const count = symtab.size / symbol_size;
    const classes = try arena.alloc(rules.Class, count);
    const symbol_names = try arena.alloc([]const u8, count);
    for (classes, symbol_names, 0..) |*class, *name, i| {
        const entry = bytes[symtab.offset + i * symbol_size ..][0..symbol_size];
        name.* = try symbolName(layout, entry, strings, report);
        class.* = try classify(layout, entry, name.*, i, symtab.info, &keep, report);
    }
    if (keep.missing()) |name| return report.refuse("{s} is to stay global, and the object defines no global symbol by that name", .{name});

    const rewrite = Rewrite{
        .arena = arena,
        .layout = layout,
        .bytes = bytes,
        .symtab_index = @intCast(symtab_index),
        .classes = classes,
        .names = symbol_names,
        .new_index = try rules.order(arena, classes),
        .report = report,
    };
    for (sections, 0..) |section, i| {
        if (i != symtab_index) try rewrite.renumber(section);
    }
    const table = bytes[symtab.offset..][0..symtab.size];
    for (classes, 0..) |class, i| {
        if (class == .localized) setBinding(layout, table[i * symbol_size ..][0..symbol_size], stb_local);
    }
    try rules.permute(arena, table, symbol_size, rewrite.new_index);
    const info_offset: usize = if (layout.elf64) 44 else 28;
    layout.write(u32, bytes, symtab.header + info_offset, rules.localCount(classes));
}

fn readLayout(bytes: []const u8, report: *rules.Report) !Layout {
    if (bytes.len < 64) return report.refuse("the file is {d} bytes, too short for an ELF header", .{bytes.len});
    const elf64 = switch (bytes[4]) {
        1 => false,
        2 => true,
        else => return report.refuse("EI_CLASS is {d}, which is neither ELFCLASS32 nor ELFCLASS64", .{bytes[4]}),
    };
    const endian: std.builtin.Endian = switch (bytes[5]) {
        1 => .little,
        2 => .big,
        else => return report.refuse("EI_DATA is {d}, which names no byte order", .{bytes[5]}),
    };
    var layout = Layout{ .endian = endian, .elf64 = elf64, .mips = false };
    const file_type = layout.read(u16, bytes, 16);
    if (file_type != et_rel) return report.refuse("e_type is {d}; only a relocatable object (ET_REL) is rewritten", .{file_type});
    layout.mips = layout.read(u16, bytes, 18) == em_mips;
    // MIPS64 splits r_info into a symbol and three relocation types, in an
    // order that depends on the byte order, so its entries do not read as
    // the r_info every other ELF64 machine writes.
    if (elf64 and layout.mips) return report.refuse("MIPS64 relocations pack r_info differently; the tool reads MIPS ELF32 only", .{});
    return layout;
}

fn readSections(arena: std.mem.Allocator, layout: Layout, bytes: []const u8, report: *rules.Report) ![]Section {
    const table_offset = layout.readWord(bytes, if (layout.elf64) 0x28 else 0x20);
    const entry_size = layout.read(u16, bytes, if (layout.elf64) 0x3a else 0x2e);
    var count: u64 = layout.read(u16, bytes, if (layout.elf64) 0x3c else 0x30);
    if (entry_size != layout.sectionHeaderSize()) return report.refuse("e_shentsize is {d}, and ELF's is {d}", .{ entry_size, layout.sectionHeaderSize() });
    if (table_offset == 0 or table_offset > bytes.len) return report.refuse("the section header table starts at {d}, outside the file", .{table_offset});
    // With 0xff00 sections or more, e_shnum is 0 and section 0's sh_size
    // holds the count.
    if (count == 0) count = layout.readWord(bytes, @as(usize, @intCast(table_offset)) + if (layout.elf64) @as(usize, 32) else 20);
    if (count > (bytes.len - table_offset) / entry_size) return report.refuse("{d} section headers do not fit in the file", .{count});

    const sections = try arena.alloc(Section, @intCast(count));
    for (sections, 0..) |*section, i| {
        const header: usize = @intCast(table_offset + i * entry_size);
        section.* = if (layout.elf64) .{
            .header = header,
            .type = layout.read(u32, bytes, header + 4),
            .offset = @intCast(layout.read(u64, bytes, header + 24)),
            .size = @intCast(layout.read(u64, bytes, header + 32)),
            .link = layout.read(u32, bytes, header + 40),
            .info = layout.read(u32, bytes, header + 44),
            .entsize = @intCast(layout.read(u64, bytes, header + 56)),
        } else .{
            .header = header,
            .type = layout.read(u32, bytes, header + 4),
            .offset = layout.read(u32, bytes, header + 16),
            .size = layout.read(u32, bytes, header + 20),
            .link = layout.read(u32, bytes, header + 24),
            .info = layout.read(u32, bytes, header + 28),
            .entsize = layout.read(u32, bytes, header + 36),
        };
        // SHT_NOBITS (8) occupies no bytes in the file, and SHT_NULL none.
        if (section.type != 8 and section.type != 0 and (section.offset > bytes.len or section.size > bytes.len - section.offset)) {
            return report.refuse("section {d} runs past the end of the file", .{i});
        }
    }
    return sections;
}

fn findSymbolTable(sections: []const Section, report: *rules.Report) !usize {
    var found: ?usize = null;
    for (sections, 0..) |section, i| {
        if (section.type == sht_dynsym) return report.refuse("section {d} is a dynamic symbol table, which a relocatable object does not carry", .{i});
        if (section.type != sht_symtab) continue;
        if (found != null) return report.refuse("the object has two symbol tables", .{});
        found = i;
    }
    return found orelse report.refuse("the object has no symbol table", .{});
}

/// Where symbol i goes, and whether its name is kept. i below sh_info must
/// be local and i at or past it must not, which is ELF's own rule; a table
/// that breaks it is refused rather than guessed at.
fn classify(layout: Layout, entry: []const u8, name: []const u8, i: usize, first_global: u32, keep: *rules.Keep, report: *rules.Report) !rules.Class {
    const binding = entry[layout.symbolInfoOffset()] >> 4;
    const index = layout.read(u16, entry, layout.symbolIndexOffset());
    if ((binding == stb_local) != (i < first_global)) {
        return report.refuse("symbol {d} breaks the rule that sh_info, {d}, separates the locals from the globals", .{ i, first_global });
    }
    if (binding == stb_local) return .local;
    if (binding != stb_global and binding != stb_weak and binding != stb_gnu_unique) {
        return report.refuse("symbol {d} has binding {d}, which the tool does not know", .{ i, binding });
    }
    if (index == shn_undef) return .global;
    const kept = keep.holds(name);
    if (kept) |k| keep.found[k] = true;
    // A common symbol has no section to be local in, and neither has one
    // of the processor-specific reserved indices, MIPS's small common
    // among them. SHN_ABS is a definition, and SHN_XINDEX names a section.
    if (index >= shn_loreserve and index != shn_abs and index != shn_xindex) {
        if (kept != null) return .global;
        return report.refuse("{s} is a common symbol (section index 0x{x}), which cannot be made local; compile with -fno-common", .{ name, index });
    }
    return if (kept != null) .global else .localized;
}

fn symbolName(layout: Layout, entry: []const u8, strings: []const u8, report: *rules.Report) ![]const u8 {
    const start = layout.read(u32, entry, 0);
    if (start >= strings.len) return report.refuse("a symbol's name starts at {d}, past its string table", .{start});
    const end = std.mem.indexOfScalarPos(u8, strings, start, 0) orelse return report.refuse("a symbol's name runs past its string table", .{});
    return strings[start..end];
}

fn setBinding(layout: Layout, entry: []u8, binding: u8) void {
    const offset = layout.symbolInfoOffset();
    entry[offset] = (binding << 4) | (entry[offset] & 0x0f);
}

/// What renumbering needs: the symbols' classes and names by their old
/// index, and the new index of each.
const Rewrite = struct {
    arena: std.mem.Allocator,
    layout: Layout,
    bytes: []u8,
    symtab_index: u32,
    classes: []const rules.Class,
    names: []const []const u8,
    new_index: []const u32,
    report: *rules.Report,

    /// Renumbers the symbol indices one section holds. A section that
    /// names the symbol table in sh_link and is none of the known kinds is
    /// refused, because it may hold indices the tool would leave stale.
    fn renumber(rewrite: Rewrite, section: Section) !void {
        const layout = rewrite.layout;
        const report = rewrite.report;
        switch (section.type) {
            sht_rel, sht_rela => {
                if (section.link != rewrite.symtab_index) return report.refuse("a relocation section names section {d} as its symbol table, and the symbol table is {d}", .{ section.link, rewrite.symtab_index });
                try rewrite.renumberRelocations(section);
            },
            sht_group => {
                if (section.link != rewrite.symtab_index) return report.refuse("a section group names section {d} as its symbol table", .{section.link});
                const info_offset: usize = if (layout.elf64) 44 else 28;
                layout.write(u32, rewrite.bytes, section.header + info_offset, try rewrite.lookUp(section.info));
            },
            sht_symtab_shndx => {
                if (section.size != rewrite.new_index.len * 4) return report.refuse("SHT_SYMTAB_SHNDX holds {d} bytes for {d} symbols", .{ section.size, rewrite.new_index.len });
                try rules.permute(rewrite.arena, rewrite.bytes[section.offset..][0..section.size], 4, rewrite.new_index);
            },
            // The address-significance table lists symbol indices for
            // lld's safe identical-code folding. A tool that reorders the
            // symbol table without rewriting it sets its sh_link to 0, and
            // lld then ignores it; Zig's partial link writes it that way.
            // The tool does the same to a table that still names the
            // symbol table, which costs the folding and nothing else.
            sht_llvm_addrsig => {
                if (section.link == rewrite.symtab_index) {
                    const link_offset: usize = if (layout.elf64) 40 else 24;
                    layout.write(u32, rewrite.bytes, section.header + link_offset, 0);
                }
            },
            else => {
                if (section.link == rewrite.symtab_index) return report.refuse("section type 0x{x} names the symbol table, and the tool does not know what it holds", .{section.type});
            },
        }
    }

    fn renumberRelocations(rewrite: Rewrite, section: Section) !void {
        const layout = rewrite.layout;
        const entry_size: usize = switch (section.type) {
            sht_rel => if (layout.elf64) 16 else 8,
            else => if (layout.elf64) 24 else 12,
        };
        if (section.entsize != entry_size or section.size % entry_size != 0) {
            return rewrite.report.refuse("a relocation section's entry size is {d}, and ELF's is {d}", .{ section.entsize, entry_size });
        }
        const info_offset: usize = if (layout.elf64) 8 else 4;
        var offset = section.offset + info_offset;
        while (offset < section.offset + section.size) : (offset += entry_size) {
            if (layout.elf64) {
                const info = layout.read(u64, rewrite.bytes, offset);
                const symbol = try rewrite.lookUp(@intCast(info >> 32));
                layout.write(u64, rewrite.bytes, offset, (@as(u64, symbol) << 32) | (info & 0xffff_ffff));
            } else {
                const info = layout.read(u32, rewrite.bytes, offset);
                try rewrite.checkMips(info >> 8, info & 0xff);
                const symbol = try rewrite.lookUp(info >> 8);
                if (symbol > 0xff_ffff) return rewrite.report.refuse("symbol index {d} does not fit ELF32's r_info", .{symbol});
                layout.write(u32, rewrite.bytes, offset, (symbol << 8) | (info & 0xff));
            }
        }
    }

    /// The MIPS ABI gives a GOT16 relocation against a local symbol another
    /// meaning than against a global one: the page of the symbol's
    /// address, completed by the LO16 relocation that must follow it.
    /// Position-independent MIPS code writes GOT16 and CALL16 against
    /// globals with no LO16 after them, so making such a symbol local
    /// changes what the linked code computes; `objcopy -G` makes the same
    /// change without a word, and lld only warns. The tool refuses it, and
    /// the XGOT forms of the two, and a MIPS object compiled without PIC
    /// writes none of them.
    fn checkMips(rewrite: Rewrite, symbol: u32, relocation_type: u32) !void {
        if (!rewrite.layout.mips or symbol >= rewrite.classes.len or rewrite.classes[symbol] != .localized) return;
        switch (relocation_type) {
            r_mips_got16, r_mips_call16, r_mips_got_hi16, r_mips_got_lo16, r_mips_call_hi16, r_mips_call_lo16 => {},
            else => return,
        }
        return rewrite.report.refuse("a MIPS GOT relocation (type {d}) names {s}, and making it local changes what that relocation means; compile MIPS without PIC", .{ relocation_type, rewrite.names[symbol] });
    }

    fn lookUp(rewrite: Rewrite, old: u32) !u32 {
        if (old >= rewrite.new_index.len) return rewrite.report.refuse("an index names symbol {d}, and the table holds {d}", .{ old, rewrite.new_index.len });
        return rewrite.new_index[old];
    }
};
