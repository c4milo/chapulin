//! colibri's image: two chapulin dependencies of different transports,
//! each imported as a module of its own and linked as an object of its
//! own. chapulin_h2 is the tcp-nonblocking ROLE=both object colibri's
//! HTTP/2 runs on, and chapulin_quic is its QUIC object; both trust
//! TRUST=webpki. The two modules declare ch_cfg with different layouts,
//! and each half uses its own module's.
//!
//! Each half reads its object's build record, then starts a client,
//! which checks the ch_cfg it is given and builds a ClientHello, as
//! test/lib_pair_half.c does for make's objects. The program exits with
//! the number of halves that failed.
const std = @import("std");
const h2 = @import("chapulin_h2");
const quic = @import("chapulin_quic");
const hooks = @import("hooks.zig");

comptime {
    hooks.define(&.{ h2, quic });
}

pub fn main() u8 {
    return startH2() + startQuic();
}

fn failed(half: []const u8, step: []const u8) u8 {
    std.debug.print("pair: the {s} half: {s}\n", .{ half, step });
    return 1;
}

// An anchor, a hostname and a clock, the configuration a TRUST=webpki
// client takes. The anchor's bytes are placeholders: the init calls check
// only that each field is set, and no certificate arrives here.
const anchor_name = [_]u8{ 0x30, 0x00 };
const anchor_spki = [_]u8{ 0x30, 0x00 };
const hostname = "dns.example";

/// The fields both clients set, in the ch_cfg of module c.
fn clientConfig(comptime c: type, buf: []u8) c.ch_cfg {
    const anchors = struct {
        const list = [_]c.ch_trust_anchor{.{
            .name = &anchor_name,
            .name_len = anchor_name.len,
            .spki = &anchor_spki,
            .spki_len = anchor_spki.len,
        }};
    };
    var cfg = std.mem.zeroes(c.ch_cfg);
    cfg.buf = buf.ptr;
    cfg.buf_len = buf.len;
    cfg.anchors = &anchors.list;
    cfg.anchor_count = anchors.list.len;
    cfg.hostname = hostname;
    cfg.hostname_len = hostname.len;
    cfg.now_seconds = 1789000000;
    return cfg;
}

// The HTTP/2 half. The first record the client hands out is a handshake
// record, content type 22 (RFC 9846 section 5.1).
const handshake_record = 22;
var h2_rx: [h2.CH_MIN_RXBUF]u8 = undefined;
var h2_flight: [h2.CH_TX_STAGE]u8 = undefined;
var h2_client: h2.ch_record = undefined;

fn keepSend(_: ?*anyopaque, _: [*c]const u8, _: usize) callconv(.c) c_int {
    return 0;
}

fn failRecv(_: ?*anyopaque, p: [*c]u8, n: usize) callconv(.c) c_int {
    @memset(p[0..n], 0);
    return -1;
}

fn startH2() u8 {
    if (h2.ch_build_matches(hooks.record(h2)) != 1) {
        return failed("h2", "ch_build_matches read a record that is not this object's");
    }
    var cfg = clientConfig(h2, &h2_rx);
    cfg.send = keepSend;
    cfg.recv = failRecv;
    if (h2.ch_record_init(&h2_client, &cfg) != h2.CH_OK) return failed("h2", "ch_record_init refused a client");
    var n: usize = 0;
    const rc = h2.ch_record_out(&h2_client, &h2_flight, h2_flight.len, &n);
    h2.ch_record_close(&h2_client);
    if (rc != h2.CH_OK or n == 0 or h2_flight[0] != handshake_record) {
        return failed("h2", "ch_record_out handed out no handshake record");
    }
    return 0;
}

// The QUIC half. RFC 9001 requires transport parameters (section 8.2)
// and an ALPN protocol (section 8.1) in every QUIC handshake, and the
// first CRYPTO bytes at the Initial level are a ClientHello, handshake
// message type 1 (RFC 9846 section 4).
const client_hello = 1;
const params = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
const alpn = [_]quic.ch_alpn_protocol{.{ .name = "h3", .name_len = 2 }};
var quic_rx: [quic.CH_MIN_RXBUF]u8 = undefined;
var quic_flight: [quic.CH_TX_STAGE]u8 = undefined;
var quic_client: quic.ch_quic = undefined;

fn levelReady(_: ?*anyopaque, _: u8, _: u8) callconv(.c) void {}

fn startQuic() u8 {
    if (quic.ch_build_matches(hooks.record(quic)) != 1) {
        return failed("quic", "ch_build_matches read a record that is not this object's");
    }
    var cfg = clientConfig(quic, &quic_rx);
    cfg.transport_params = &params;
    cfg.transport_params_len = params.len;
    cfg.on_level_ready = levelReady;
    cfg.alpn_protocols = &alpn;
    cfg.alpn_count = alpn.len;
    if (quic.ch_quic_init(&quic_client, &cfg) != quic.CH_OK) return failed("quic", "ch_quic_init refused a client");
    var n: usize = 0;
    const rc = quic.ch_quic_crypto_out(&quic_client, quic.CH_LEVEL_INITIAL, &quic_flight, quic_flight.len, &n);
    quic.ch_quic_close(&quic_client);
    if (rc != quic.CH_OK or n == 0 or quic_flight[0] != client_hello) {
        return failed("quic", "ch_quic_crypto_out handed out no ClientHello");
    }
    return 0;
}
