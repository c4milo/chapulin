//! The Zig API's Ticket: a NewSessionTicket that outlives the session, which chapulin.zig declares
//! as chapulin.Ticket. It sits in a file of its own because chapulin.zig stood at the 500-line cap
//! CLAUDE.md sets and make lint-size holds. docs/zig.md is the reference.
const std = @import("std");
const chapulin = @import("chapulin.zig");
const c = chapulin.c;
const quic = chapulin.quic;

// The fields a TRUST=webpki ticket and a QUIC ticket add, as chapulin.zig reads them.
const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_quic = @hasField(c.ch_cfg, "quic_original_version");

/// A NewSessionTicket (RFC 9846 §4.6.1) that outlives the session: the
/// ch_ticket on_ticket received, by value, and the identity bytes it
/// pointed at. A program that copies a Ticket owns zeroing that copy.
pub const Ticket = struct {
    /// The ch_ticket on_ticket received. Its identity pointer is null here, because the bytes it
    /// named are valid during on_ticket alone. psk, psk_len, age_add, lifetime_s, epoch, under
    /// TRUST=webpki binding and under TRANSPORT=quic-nonblocking quic_version are read from it
    /// under their C names.
    ticket: c.ch_ticket,
    /// The identity bytes, ticket.identity_len of them, presented as psk_id.
    identity: [c.CH_TICKET_ID_MAX]u8,

    /// The fields fromFields takes. binding is the ticket's ch_ticket.binding, which a TRUST=webpki
    /// object alone has, and quic_version its ch_ticket.quic_version, a QUIC object's alone, whose
    /// null init refuses as a resuming ticket's version.
    pub const Fields = if (has_webpki) struct {
        identity: []const u8,
        psk: []const u8,
        age_add: u32,
        lifetime_s: u32,
        epoch: u32 = 0,
        binding: *const [c.SHA256_LEN]u8,
        quic_version: if (has_quic) ?quic.Version else void = if (has_quic) null else {},
    } else struct {
        identity: []const u8,
        psk: []const u8,
        age_add: u32,
        lifetime_s: u32,
        epoch: u32 = 0,
        quic_version: if (has_quic) ?quic.Version else void = if (has_quic) null else {},
    };

    /// A Ticket rebuilt from fields a program stored after an earlier handshake, for a program that
    /// keeps its own ticket value across connections and objects. It refuses an identity longer
    /// than CH_TICKET_ID_MAX or a psk that is not a hash length this object holds, SHA256_LEN or,
    /// where HKDF_HASH_MAX is SHA384_LEN, that too. Setting ticket's fields by hand is not
    /// supported.
    pub fn fromFields(fields: Fields) error{Invalid}!Ticket {
        const psk_ok = fields.psk.len == c.SHA256_LEN or fields.psk.len == c.HKDF_HASH_MAX;
        if (fields.identity.len > c.CH_TICKET_ID_MAX or !psk_ok) return error.Invalid;
        var out: Ticket = .{ .ticket = std.mem.zeroes(c.ch_ticket), .identity = @splat(0) };
        @memcpy(out.identity[0..fields.identity.len], fields.identity);
        @memcpy(out.ticket.psk[0..fields.psk.len], fields.psk);
        out.ticket.identity_len = fields.identity.len;
        out.ticket.psk_len = fields.psk.len;
        out.ticket.age_add = fields.age_add;
        out.ticket.lifetime_s = fields.lifetime_s;
        out.ticket.epoch = fields.epoch;
        if (has_webpki) out.ticket.binding = fields.binding.*;
        if (has_quic) out.ticket.quic_version = quic.versionCode(fields.quic_version);
        return out;
    }

    /// A copy of the ch_ticket on_ticket hands over, identity bytes and
    /// all, or null for an identity longer than CH_TICKET_ID_MAX, which C
    /// drops before on_ticket. The sessions' own on_ticket calls it.
    pub fn fromOnTicket(ticket: *const c.ch_ticket) ?Ticket {
        if (ticket.identity_len > c.CH_TICKET_ID_MAX or ticket.identity == null) return null;
        var out: Ticket = .{ .ticket = ticket.*, .identity = @splat(0) };
        @memcpy(out.identity[0..ticket.identity_len], ticket.identity[0..ticket.identity_len]);
        out.ticket.identity = null;
        return out;
    }
};
