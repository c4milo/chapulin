#!/usr/bin/env python3
"""Draws the revocation-epoch sequence diagrams in docs/img.

Run from the repository root: python3 docs/gen_epoch_diagrams.py

The SVGs are generated, never hand-edited: change this script and
re-run it. Each diagram paints its own background so it reads the same
in a light or a dark viewer. Output is plain SVG with no external
fonts, scripts, or images, so it renders anywhere and diffs as text.
"""

import pathlib

BG = "#ffffff"
INK = "#1b1f24"
MUTED = "#57606a"
LIFE = "#8c959f"
BLUE = "#0969da"
GREEN = "#1a7f37"
RED = "#cf222e"
NOTE_BG = "#fff8c5"
NOTE_EDGE = "#d4a72c"
STATE_BG = "#ddf4ff"
STATE_EDGE = "#54aeff"

FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

PAD = 34          # canvas margin outside the outermost lifeline
TITLE_Y = 34      # title baseline
SUB_Y = 55        # subtitle baseline
TOP = 128         # first row; header boxes sit at TOP-46, clear of SUB_Y
ROW = 46
NOTE_PAD = 11
MIN_COL = 250


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text_w(s, size, mono=False):
    """Width of a string in pixels, erring high so nothing collides."""
    per = 0.62 if mono else 0.55
    return int(len(s) * size * per) + 2


class Diagram:
    """A sequence diagram. Columns and canvas are sized from content,
    so no box or label can land outside the image or on a neighbour."""

    def __init__(self, title, subtitle, actors):
        self.title = title
        self.subtitle = subtitle
        self.actors = actors
        self.rows = []
        self.col_w = MIN_COL
        self.head_w = 156

    def msg(self, src, dst, label, tone=INK, dashed=False):
        self.rows.append(("msg", src, dst, label, tone, dashed))

    def note(self, actor, lines, tone="note"):
        self.rows.append(("note", actor, lines, tone))

    def state(self, actor, label):
        self.rows.append(("state", actor, label))

    def gap(self, height=14):
        self.rows.append(("gap", height))

    def _size(self, verdict):
        """Column width from the widest label, header width from the
        widest actor name, then the canvas wide enough for every one
        of them plus the title block and the verdict banner."""
        for row in self.rows:
            if row[0] == "msg":
                span = max(1, abs(row[2] - row[1]))
                need = (text_w(row[3], 12, mono=True) + 44) // span
                self.col_w = max(self.col_w, need)
        for name in self.actors:
            self.head_w = max(self.head_w, text_w(name, 12.5) + 28)
        self.col_w = max(self.col_w, self.head_w + 16)
        left = PAD + self.head_w // 2
        width = left * 2 + (len(self.actors) - 1) * self.col_w
        # A note wider than the canvas widens the canvas, never the note.
        for row in self.rows:
            if row[0] == "note":
                w = max(text_w(t, 11.5) for t in row[2]) + 2 * NOTE_PAD
                width = max(width, w + 2 * PAD)
        # The title block and the verdict banner span the whole image.
        width = max(width, text_w(self.title, 17) + 2 * PAD)
        width = max(width, text_w(self.subtitle, 12.5) + 2 * PAD)
        width = max(width, text_w(verdict, 12.5) + 2 * PAD + 28)
        return left, width

    def x(self, i):
        return self.left + i * self.col_w

    def _layout(self):
        y = TOP
        placed = []
        for row in self.rows:
            if row[0] == "gap":
                y += row[1]
            elif row[0] == "note":
                placed.append((y, row))
                y += 20 + 17 * len(row[2]) + 12
            elif row[0] == "state":
                placed.append((y, row))
                y += 34
            else:
                placed.append((y, row))
                y += ROW
        return placed, y

    def render(self, verdict_tone, verdict):
        self.left, width = self._size(verdict)
        placed, y = self._layout()
        bottom = y + 56
        boxes = []  # every drawn rect, checked against the canvas below
        out = []
        add = out.append
        add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{bottom}" viewBox="0 0 {width} {bottom}" '
            f'font-family="{FONT}" role="img" '
            f'aria-label="{esc(self.title)}">')
        add(f'<rect width="{width}" height="{bottom}" fill="{BG}"/>')
        add('<defs>'
            f'<marker id="a" markerWidth="9" markerHeight="9" refX="8" refY="3" '
            f'orient="auto"><path d="M0,0 L8,3 L0,6 z" fill="{INK}"/></marker>'
            f'<marker id="ar" markerWidth="9" markerHeight="9" refX="8" refY="3" '
            f'orient="auto"><path d="M0,0 L8,3 L0,6 z" fill="{RED}"/></marker>'
            f'<marker id="ag" markerWidth="9" markerHeight="9" refX="8" refY="3" '
            f'orient="auto"><path d="M0,0 L8,3 L0,6 z" fill="{GREEN}"/></marker>'
            '</defs>')
        add(f'<text x="{PAD}" y="{TITLE_Y}" font-size="17" font-weight="600" '
            f'fill="{INK}">{esc(self.title)}</text>')
        add(f'<text x="{PAD}" y="{SUB_Y}" font-size="12.5" fill="{MUTED}">'
            f'{esc(self.subtitle)}</text>')

        boxes.append((PAD, text_w(self.title, 17), TITLE_Y - 14, 18))
        boxes.append((PAD, text_w(self.subtitle, 12.5), SUB_Y - 11, 15))

        for i, name in enumerate(self.actors):
            cx = self.x(i)
            hw = self.head_w
            add(f'<line x1="{cx}" y1="{TOP - 16}" x2="{cx}" y2="{y - 6}" '
                f'stroke="{LIFE}" stroke-width="1" stroke-dasharray="4 4"/>')
            add(f'<rect x="{cx - hw // 2}" y="{TOP - 46}" width="{hw}" height="28" '
                f'rx="6" fill="{BG}" stroke="{BLUE if i == 0 else LIFE}" '
                f'stroke-width="1.4"/>')
            boxes.append((cx - hw // 2, hw, TOP - 46, 28))
            add(f'<text x="{cx}" y="{TOP - 27}" font-size="12.5" font-weight="600" '
                f'text-anchor="middle" fill="{INK}">{esc(name)}</text>')

        for top, row in placed:
            if row[0] == "msg":
                _, src, dst, label, tone, dashed = row
                x1, x2 = self.x(src), self.x(dst)
                head = "ar" if tone == RED else ("ag" if tone == GREEN else "a")
                sign = 1 if x2 > x1 else -1
                dash = ' stroke-dasharray="6 4"' if dashed else ""
                add(f'<line x1="{x1 + sign * 4}" y1="{top}" x2="{x2 - sign * 10}" '
                    f'y2="{top}" stroke="{tone}" stroke-width="1.6" '
                    f'marker-end="url(#{head})"{dash}/>')
                # An opaque strip behind the label keeps the lifelines
                # and the arrow from striking through the glyphs.
                lw = text_w(label, 12, mono=True)
                mid = (x1 + x2) // 2
                add(f'<rect x="{mid - lw // 2 - 5}" y="{top - 22}" width="{lw + 10}" '
                    f'height="18" fill="{BG}"/>')
                boxes.append((mid - lw // 2 - 5, lw + 10, top - 22, 18))
                add(f'<text x="{mid}" y="{top - 8}" font-size="12" '
                    f'text-anchor="middle" fill="{tone}" font-family="{MONO}">'
                    f'{esc(label)}</text>')
            elif row[0] == "state":
                _, actor, label = row
                cx = self.x(actor)
                w = text_w(label, 12, mono=True) + 26
                x0 = min(max(cx - w // 2, PAD), width - PAD - w)
                add(f'<rect x="{x0}" y="{top - 15}" width="{w}" height="26" rx="13" '
                    f'fill="{STATE_BG}" stroke="{STATE_EDGE}"/>')
                boxes.append((x0, w, top - 15, 26))
                add(f'<text x="{x0 + w // 2}" y="{top + 3}" font-size="12" '
                    f'text-anchor="middle" fill="{INK}" font-family="{MONO}">'
                    f'{esc(label)}</text>')
            else:
                _, actor, lines, tone = row
                cx = self.x(actor)
                w = max(text_w(t, 11.5) for t in lines) + 2 * NOTE_PAD
                height = 12 + 17 * len(lines)
                # Clamp inside the canvas; _size already widened it if
                # the note could not fit between the margins.
                x0 = min(max(cx - w // 2, PAD), width - PAD - w)
                fill = NOTE_BG if tone == "note" else STATE_BG
                edge = NOTE_EDGE if tone == "note" else STATE_EDGE
                add(f'<rect x="{x0}" y="{top - 8}" width="{w}" height="{height}" '
                    f'rx="5" fill="{fill}" stroke="{edge}"/>')
                boxes.append((x0, w, top - 8, height))
                for k, text in enumerate(lines):
                    add(f'<text x="{x0 + NOTE_PAD}" y="{top + 9 + 17 * k}" '
                        f'font-size="11.5" fill="{INK}">{esc(text)}</text>')

        colour = GREEN if verdict_tone == "ok" else RED
        vw = width - 2 * PAD
        add(f'<rect x="{PAD}" y="{y + 6}" width="{vw}" height="34" rx="6" '
            f'fill="{colour}" fill-opacity="0.10" stroke="{colour}"/>')
        boxes.append((PAD, vw, y + 6, 34))
        add(f'<text x="{PAD + 14}" y="{y + 28}" font-size="12.5" font-weight="600" '
            f'fill="{colour}">{esc(verdict)}</text>')
        add('</svg>')

        # Nothing may leave the canvas, and no two boxes that share
        # rows may overlap. Both are checked here rather than trusted,
        # because a diagram that reads wrong is worse than none.
        for a in range(len(boxes)):
            for b in range(a + 1, len(boxes)):
                ax, aw, ay, ah = boxes[a]
                bx, bw, by, bh = boxes[b]
                if ax < bx + bw and bx < ax + aw and ay < by + bh and by < ay + ah:
                    raise AssertionError(
                        f"{self.title}: two boxes overlap at "
                        f"({ax},{ay}) and ({bx},{by})")
        for x0, w, _, _ in boxes:
            assert x0 >= 0 and x0 + w <= width, (
                f"{self.title}: a box runs from {x0} to {x0 + w}, "
                f"outside the {width}px canvas")
        assert text_w(self.title, 17) + PAD <= width, f"{self.title}: title too wide"
        assert text_w(self.subtitle, 12.5) + PAD <= width, f"{self.title}: subtitle too wide"
        assert text_w(verdict, 12.5) + PAD + 14 <= width, f"{self.title}: verdict too wide"
        return "\n".join(out)


def revoke_compromised():
    d = Diagram("1. Revoking a compromised certificate",
                "A thief has controller-01's private key. Two steps retire it.",
                ["CA", "controller-01", "Device"])
    d.note(2, ["stored epoch = 2, like the rest of the fleet."], tone="state")
    d.note(0, ["Step 1: generate a new key pair for the server.",
               "Step 2: issue its certificate at epoch 3."])
    d.msg(0, 1, "new key + certificate (epoch 3)", tone=GREEN)
    d.gap()
    d.msg(2, 1, "ClientHello")
    d.msg(1, 2, "Certificate (epoch 3), CertificateVerify, Finished")
    d.note(2, ["3 is above 2 and within the bound, and the",
               "server proved it holds the new key.",
               "stored epoch = 3, then epoch_store(3)."], tone="state")
    d.gap(18)
    d.note(2, ["The thief still holds the old key, which matches",
               "only the epoch-2 certificate. That is now below",
               "the stored 3, so the device refuses it with",
               "certificate_revoked."])
    return d.render("ok", "The stolen key no longer authenticates anywhere in the fleet.")


def bootstrap_device():
    d = Diagram("2. Bootstrapping a new device",
                "A device joins a fleet that has already revoked a few times.",
                ["Provisioning", "Device", "Server"])
    d.note(0, ["Write the CA public key and the fleet's current",
               "epoch, 3. Both go in before the device ships."])
    d.msg(0, 1, "CA key + epoch 3", tone=GREEN)
    d.gap()
    d.msg(1, 2, "ClientHello  (first ever connect)")
    d.msg(2, 1, "Certificate (epoch 3), CertificateVerify, Finished")
    d.note(1, ["3 equals the stored 3: CH_EPOCH_MATCHED.",
               "The stored value does not change, so nothing",
               "is written."], tone="state")
    d.gap(18)
    d.note(1, ["Provision the current epoch, not an old one.",
               "A device boxed at epoch 3 while the fleet moves",
               "on has only CH_EPOCH_BOUND steps of shelf life",
               "before it can no longer join."])
    return d.render("ok", "The device joins with no flash write at all.")


def device_returns():
    d = Diagram("3. A device returns after downtime",
                "It slept through several revocations and has to catch up.",
                ["Device", "Server"])
    d.state(0, "stored epoch = 2")
    d.note(1, ["The fleet has revoked three times since.",
               "Servers now carry epoch 5."])
    d.msg(0, 1, "ClientHello")
    d.msg(1, 0, "Certificate (epoch 5)")
    d.note(0, ["5 - 2 = 3 steps, well inside the bound of 64.",
               "One handshake covers any number of missed",
               "steps, so long as the gap fits the bound."], tone="state")
    d.msg(1, 0, "CertificateVerify, Finished")
    d.state(0, "stored epoch = 5")
    d.gap(16)
    d.note(0, ["Past the bound the device would answer",
               "bad_certificate instead, and only reprovisioning",
               "brings it back."])
    return d.render("ok", "The device catches up in one handshake, skipping the epochs it missed.")


def rotate_certificates():
    d = Diagram("4. Rotating certificates routinely",
                "Ordinary reissuance keeps the same epoch, so no device moves.",
                ["CA", "controller-01", "Device"])
    d.note(2, ["stored epoch = 3, along with the whole fleet."], tone="state")
    d.note(0, ["Routine reissuance: a fresh certificate, and a",
               "fresh key pair if you rotate on a schedule. The",
               "epoch date does not change."])
    d.msg(0, 1, "new certificate, still epoch 3", tone=GREEN)
    d.gap()
    d.msg(2, 1, "ClientHello")
    d.msg(1, 2, "Certificate (epoch 3), CertificateVerify, Finished")
    d.note(2, ["3 equals the stored 3: CH_EPOCH_MATCHED.",
               "Nothing moves, nothing is written, nothing to",
               "roll out."], tone="state")
    d.gap(18)
    d.note(2, ["Rotation on its own does not revoke anything.",
               "A thief holding an old key still has a valid",
               "epoch-3 certificate until you advance the epoch.",
               "That is use case 1."])
    return d.render("ok", "Rotate as often as you like: only advancing the epoch moves devices.")


def rollout_partition():
    d = Diagram("5. Rolling out a new epoch",
                "Reissuing servers one at a time splits the fleet.",
                ["Device", "Server A (reissued)", "Server B (waiting)"])
    d.state(0, "stored epoch = 2")
    d.msg(0, 1, "ClientHello")
    d.msg(1, 0, "Certificate (epoch 3)")
    d.note(0, ["The handshake completes, so the device",
               "moves forward to 3."], tone="state")
    d.gap(16)
    d.msg(0, 2, "ClientHello")
    d.msg(2, 0, "Certificate (epoch 2)", tone=RED)
    d.note(0, ["2 is below the stored 3, so this server now",
               "looks revoked. The device cannot use it until",
               "the rollout gets there."])
    d.msg(0, 2, "alert certificate_revoked", tone=RED)
    return d.render("bad", "Stage every certificate first and cut over together, or treat the "
                           "window as an outage.")


def resumption_after_bump():
    d = Diagram("6. Resuming with a ticket from an older epoch",
                "A resumed session sends no certificate, so the ticket carries the epoch.",
                ["Device", "Server"])
    d.state(0, "stored epoch = 3")
    d.note(0, ["The saved ticket was issued at epoch 2, before",
               "the epoch advanced. The application presents it as",
               "cfg.ticket_epoch = 2."])
    d.gap()
    d.note(0, ["ch_connect compares 2 against the stored 3 and",
               "refuses: CH_EPOCH_REVOKED, CH_EAUTH.",
               "No socket is opened and no byte is sent."])
    d.msg(0, 1, "(nothing sent)", tone=RED, dashed=True)
    d.gap()
    d.note(0, ["The application drops the ticket and connects",
               "again in full. That handshake carries a",
               "certificate, which the epoch rule can check."])
    return d.render("bad", "Advancing the epoch retires every ticket issued before it.")


def replay_attack():
    d = Diagram("7. An attacker replays a certificate",
                "Certificates are public, so holding one proves nothing.",
                ["Device", "Attacker"])
    d.state(0, "stored epoch = 2")
    d.note(1, ["The attacker connected to a real server as an",
               "ordinary client and copied its epoch-3 certificate.",
               "The attacker has no private key."])
    d.gap()
    d.msg(0, 1, "ClientHello")
    d.msg(1, 0, "Certificate (epoch 3, genuine)")
    d.note(0, ["The chain verifies and 3 is within the bound,",
               "so the rule judges the certificate. It writes",
               "nothing. Had it moved the stored value here,",
               "this handshake",
               "would have pushed the device to 3 for good."])
    d.msg(1, 0, "CertificateVerify  (cannot sign)", tone=RED)
    d.note(0, ["The signature fails: no private key.",
               "epoch_commit never runs."])
    d.msg(0, 1, "alert decrypt_error", tone=RED)
    d.state(0, "stored epoch = 2")
    return d.render("bad", "The device stays at 2 and can still talk to epoch-2 servers.")


DIAGRAMS = {
    "epoch-revoke": revoke_compromised,
    "epoch-bootstrap": bootstrap_device,
    "epoch-catch-up": device_returns,
    "epoch-rotate": rotate_certificates,
    "epoch-rollout": rollout_partition,
    "epoch-resumption": resumption_after_bump,
    "epoch-replay": replay_attack,
}


def main():
    out_dir = pathlib.Path("docs/img")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, build in DIAGRAMS.items():
        path = out_dir / f"{name}.svg"
        path.write_text(build() + "\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
