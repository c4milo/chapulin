//! A ceiling for bench/record.c on the same machine: Zig's std.crypto
//! AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 over the records
//! bench/record.c times, with its statistics: each figure is the median of
//! five runs, each run the median of 15 batches of at least 1 ms, the seal
//! and open batches interleaved. bench/record.sh builds this with the zig
//! on PATH when it is the pinned version and adds its rows to the CSV. It
//! is not chapulin code, and nothing in chapulin links it.
//!
//! Each seal runs in place, as rec_seal seals, over the plaintext and its
//! content type byte with the 5-byte header as associated data. Each open
//! reads a sealed copy and writes another buffer, so its input stays
//! valid and no refill runs. std.crypto expands the key inside every call,
//! as record.c does for every record, so these rows compare with rec_seal
//! and rec_open rather than with the AEAD rows that reuse a schedule.
const std = @import("std");
const Io = std.Io;
const aead = std.crypto.aead;

const record_sizes = [_]usize{ 1024, 16384, 65536 };
const max_len = 65536 + 1;
const header_len = 5;
const runs = 5;
const samples = 15;
const batch_ns: i96 = 1_000_000;

fn now(io: Io) i96 {
    return Io.Clock.awake.now(io).nanoseconds;
}

/// One AEAD's buffers and the two operations the rows time.
fn Bench(comptime A: type) type {
    return struct {
        const Self = @This();
        key: [A.key_length]u8 = undefined,
        nonce: [A.nonce_length]u8 = undefined,
        header: [header_len]u8 = undefined,
        buf: [max_len]u8 = undefined,
        sealed: [max_len]u8 = undefined,
        out: [max_len]u8 = undefined,
        tag: [A.tag_length]u8 = undefined,
        sealed_tag: [A.tag_length]u8 = undefined,
        len: usize = 0,

        fn prepare(b: *Self, random: std.Random, plaintext_len: usize) void {
            b.len = plaintext_len + 1;
            random.bytes(&b.key);
            random.bytes(&b.nonce);
            random.bytes(&b.header);
            random.bytes(b.buf[0..b.len]);
            A.encrypt(b.sealed[0..b.len], &b.sealed_tag, b.buf[0..b.len], &b.header, b.nonce, b.key);
        }

        fn seal(b: *Self) void {
            A.encrypt(b.buf[0..b.len], &b.tag, b.buf[0..b.len], &b.header, b.nonce, b.key);
            std.mem.doNotOptimizeAway(&b.tag);
        }

        fn open(b: *Self) void {
            A.decrypt(b.out[0..b.len], b.sealed[0..b.len], b.sealed_tag, &b.header, b.nonce, b.key) catch
                @panic("std.crypto rejected its own record");
            std.mem.doNotOptimizeAway(&b.out);
        }
    };
}

/// One row at one size: its batch, and each batch's time per operation.
const Cell = struct {
    repetitions: usize = 1,
    batch_ns: [runs][samples]f64 = undefined,
};

fn timeBatch(io: Io, b: anytype, comptime op: anytype, repetitions: usize) f64 {
    const start = now(io);
    for (0..repetitions) |_| op(b);
    return @floatFromInt(now(io) - start);
}

fn median(values: []f64) f64 {
    std.mem.sort(f64, values, {}, std.sort.asc(f64));
    return values[values.len / 2];
}

fn printRow(out: *Io.Writer, name: []const u8, stage: []const u8, bytes: usize, cell: *const Cell) !void {
    var run_figures: [runs]f64 = undefined;
    var all: [runs * samples]f64 = undefined;
    for (0..runs) |run| {
        var batches = cell.batch_ns[run];
        run_figures[run] = median(&batches);
        @memcpy(all[run * samples ..][0..samples], &cell.batch_ns[run]);
    }
    const ns = median(&run_figures);
    std.mem.sort(f64, &all, {}, std.sort.asc(f64));
    const size: f64 = @floatFromInt(bytes);
    try out.print("{s},zig {s} std.crypto,{s},{d},{d:.1},{d:.4},{d:.1},{d:.1},{d:.1},{d:.1}\n", .{
        name,                           @import("builtin").zig_version_string,
        stage,                          bytes,
        ns,                             ns / size,
        1000.0 * size / ns,             100.0 * (run_figures[runs - 1] - run_figures[0]) / ns,
        all[(runs * samples - 1) / 10], all[9 * (runs * samples - 1) / 10],
    });
}

fn measure(io: Io, out: *Io.Writer, random: std.Random, comptime A: type, name: []const u8) !void {
    const S = Bench(A);
    const state = struct {
        var bench: S = .{};
    };
    const b = &state.bench;
    var seal_cells = [_]Cell{.{}} ** record_sizes.len;
    var open_cells = [_]Cell{.{}} ** record_sizes.len;
    // The warm-up fixes each batch: the operation count doubles until one
    // batch takes batch_ns.
    for (record_sizes, 0..) |size, s| {
        b.prepare(random, size);
        while (timeBatch(io, b, S.seal, seal_cells[s].repetitions) < batch_ns) seal_cells[s].repetitions *= 2;
        while (timeBatch(io, b, S.open, open_cells[s].repetitions) < batch_ns) open_cells[s].repetitions *= 2;
    }
    for (0..runs) |run| {
        for (record_sizes, 0..) |size, s| {
            b.prepare(random, size);
            for (0..samples) |i| {
                const seal_reps = seal_cells[s].repetitions;
                const open_reps = open_cells[s].repetitions;
                seal_cells[s].batch_ns[run][i] = timeBatch(io, b, S.seal, seal_reps) / @as(f64, @floatFromInt(seal_reps));
                open_cells[s].batch_ns[run][i] = timeBatch(io, b, S.open, open_reps) / @as(f64, @floatFromInt(open_reps));
            }
        }
    }
    for (record_sizes, 0..) |size, s| {
        try printRow(out, name, "zig_seal", size, &seal_cells[s]);
        try printRow(out, name, "zig_open", size, &open_cells[s]);
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var buffer: [4096]u8 = undefined;
    // Streaming, because bench/record.sh sends every program's rows to one
    // file: the positional writer writes at the file's start, over the rows
    // the programs before it wrote.
    var writer = Io.File.stdout().writerStreaming(io, &buffer);
    const out = &writer.interface;
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    const random = prng.random();
    try measure(io, out, random, aead.aes_gcm.Aes128Gcm, "aes128gcm");
    try measure(io, out, random, aead.aes_gcm.Aes256Gcm, "aes256gcm");
    try measure(io, out, random, aead.chacha_poly.ChaCha20Poly1305, "chacha20poly1305");
    try out.flush();
}
