//! colibri's image: two chapulin dependencies of different transports,
//! each imported as a module of its own, and each module carrying its own
//! object. chapulin_h2 is the tcp-nonblocking ROLE=both object colibri's
//! HTTP/2 runs on, and chapulin_quic is its QUIC object; both trust
//! TRUST=webpki. The two modules declare ch_cfg with different layouts,
//! and each half uses its own module's.
//!
//! Each half reads its object's build record, computes a ticket's
//! obfuscated age through the call ticket.h names for its transport, both
//! directly and through its module's Client.toCfg, then starts a client
//! through the module's API, which checks the ch_cfg it is given and
//! builds a ClientHello, as test/lib_pair_half.c does for make's objects.
//! The program exits with the number of halves that failed.
const std = @import("std");
const h2 = @import("chapulin_h2");
const quic = @import("chapulin_quic");
const hooks = @import("hooks.zig");

comptime {
    hooks.define(&.{ h2.c, quic.c });
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

/// The values both clients set, in the Client of module api.
fn clientValues(comptime api: type) api.Client {
    const anchors = struct {
        const list = [_]api.c.ch_trust_anchor{api.trustAnchor(&anchor_name, &anchor_spki)};
    };
    return .{ .trust = .{ .web_pki = .{
        .anchors = &anchors.list,
        .server_name = hostname,
        .now_seconds = 1789000000,
    } } };
}

/// Whether module api's ch_ticket_obfuscated_age adds a ticket's age_add
/// to its age modulo 2^32 (RFC 9846 section 4.3.11.1), called directly and
/// through Client.toCfg. Each module's name maps to its own object's
/// symbol, so each half calls its own object.
fn ticketAgeAdds(comptime api: type) bool {
    const age_ms: u64 = (1 << 32) + 0x20;
    var direct = std.mem.zeroes(api.c.ch_ticket);
    direct.age_add = 0xffff_fff0;
    const binding = [_]u8{0} ** api.c.SHA256_LEN;
    const psk = [_]u8{1} ** api.c.SHA256_LEN;
    const ticket = api.Ticket.fromFields(.{
        .identity = "id",
        .psk = &psk,
        .age_add = 0xffff_fff0,
        .lifetime_s = 1,
        .binding = &binding,
    }) catch return false;
    var values = clientValues(api);
    values.ticket = &ticket;
    values.ticket_age_ms = age_ms;
    const cfg = values.toCfg();
    return api.c.ch_ticket_obfuscated_age(&direct, age_ms) == 0x10 and
        cfg.obfuscated_age == 0x10 and cfg.ticket_age_ms == age_ms;
}

// The HTTP/2 half. The first record the client hands out is a handshake
// record, content type 22 (RFC 9846 section 5.1).
const handshake_record = 22;
var h2_flight: [h2.c.CH_TX_STAGE]u8 = undefined;
var h2_client: h2.record.Client(h2.c.CH_MIN_RXBUF) = undefined;

fn startH2() u8 {
    if (h2.c.ch_build_matches(hooks.record(h2.c)) != 1 or !h2.buildMatches()) {
        return failed("h2", "ch_build_matches read a record that is not this object's");
    }
    if (!ticketAgeAdds(h2)) return failed("h2", "ch_ticket_obfuscated_age did not add age_add modulo 2^32");
    h2_client.init(clientValues(h2)) catch return failed("h2", "record.Client.init refused a client");
    const n = h2_client.recordOut(&h2_flight) catch 0;
    h2_client.recordClose();
    if (n == 0 or h2_flight[0] != handshake_record) {
        return failed("h2", "recordOut handed out no handshake record");
    }
    return 0;
}

// The QUIC half. RFC 9001 requires transport parameters (section 8.2)
// and an ALPN protocol (section 8.1) in every QUIC handshake, and the
// first CRYPTO bytes at the Initial level are a ClientHello, handshake
// message type 1 (RFC 9846 section 4).
const client_hello = 1;
const params = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
const alpn = [_]quic.c.ch_alpn_protocol{quic.alpnProtocol("h3")};
var quic_flight: [quic.c.CH_TX_STAGE]u8 = undefined;
var quic_peer_params: [64]u8 = undefined;
var quic_client: quic.quic.Client(quic.c.CH_MIN_RXBUF) = undefined;

fn startQuic() u8 {
    if (quic.c.ch_build_matches(hooks.record(quic.c)) != 1 or !quic.buildMatches()) {
        return failed("quic", "ch_build_matches read a record that is not this object's");
    }
    if (!ticketAgeAdds(quic)) return failed("quic", "ch_ticket_obfuscated_age did not add age_add modulo 2^32");
    var values = clientValues(quic);
    values.alpn = &alpn;
    quic_client.init(values, &params, &quic_peer_params) catch return failed("quic", "quic.Client.init refused a client");
    const n = quic_client.cryptoOut(.initial, &quic_flight) catch 0;
    quic_client.close();
    if (n == 0 or quic_flight[0] != client_hello) {
        return failed("quic", "cryptoOut handed out no ClientHello");
    }
    return 0;
}
