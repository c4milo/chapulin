#!/usr/bin/env python3
"""Draws docs/img/inplace-<os>-<arch>-<compiler>.svg: the in-place read and write beside the
calls that copy, one chart for each bench/results-inplace-*.csv that bench/inplace.sh wrote.

    python3 tools/inplace_chart.py

Each bar is the in-place call's speed in multiples of the copying call's: the CSV's speed, the
median over pairs of runs, one of each program back to back, of the copying run's time over the
in-place run's. Its whisker spans the pairs' 25th to 75th percentile. The copying calls are ch_read and ch_write over
callbacks that copy (TRANSPORT=tcp-blocking), and the in-place calls are ch_read_in_place and
ch_seal_in_place (TRANSPORT=tcp-nonblocking, docs/decisions.md 247 and 248). A chart holds a
section for reads, per record, and one for writes, per call, and a row for each size with a bar
for each AEAD.

tools/bench-numbers.py calls check_charts, so `make lint-bench-numbers` fails when a committed
SVG is not what this file draws from its CSV, when an SVG has no CSV, or when docs/performance.md
does not show a chart. After a run of bench/inplace.sh, run this file and commit its SVGs with
the CSV. The output holds no date or time of its own, so the same CSV draws the same bytes.
"""
import csv
import glob
import math
import os
import re
import sys

from speed_chart import bar, cpu_name, escape

CSV_GLOB = "bench/results-inplace-*.csv"
IMG = "docs/img"
DOC = "docs/performance.md"

# The AEADs, in the order of their bars, with each one's name and fill.
AEADS = [
    ("aes128gcm", "AES-128-GCM", "--first"),
    ("aes256gcm", "AES-256-GCM", "--second"),
    ("chacha20poly1305", "ChaCha20-Poly1305", "--third"),
]

# The sections, in order: the CSV's direction, the heading and the unit of a figure.
SECTIONS = [
    ("read", "Reads, per record", "ch_read_in_place beside ch_read"),
    ("write", "Writes, per call", "ch_seal_in_place beside ch_write"),
]

STYLE = '''<style>
svg { --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#8a8984; --grid:#e4e3df; --first:#2a78d6; --second:#eb6834; --third:#009e73; --unit:#52514e; }
@media (prefers-color-scheme: dark) {
  svg { --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --muted:#8f8e86; --grid:#33332f; --first:#3987e5; --second:#d95926; --third:#1fb386; --unit:#c3c2b7; }
}
text { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: var(--ink); }
.title { font-size: 17px; font-weight: 600; }
.sub { font-size: 12.5px; fill: var(--ink2); }
.section { font-size: 13.5px; font-weight: 600; }
.row { font-size: 12.5px; fill: var(--ink2); }
.val { font-size: 10.5px; font-weight: 600; paint-order: stroke; stroke: var(--surface); stroke-width: 3px; stroke-linejoin: round; }
.tick { font-size: 11px; fill: var(--muted); }
.legend { font-size: 12.5px; fill: var(--ink2); }
.whisker { stroke: var(--ink2); stroke-width: 1.2; }
</style>'''


def chart_path(csv_path):
    """The SVG a CSV draws: its name with results- replaced by docs/img's inplace-."""
    stem = os.path.basename(csv_path)[len("results-"):-len(".csv")]
    return "%s/%s.svg" % (IMG, stem)


def read_run(path):
    """A CSV's facts and rows: the CPU, the system, the date and the tree from its first
    comment line, the compiler from its second, and each row as a dict."""
    with open(path) as f:
        lines = f.read().splitlines()
    comments = [line[2:] for line in lines if line.startswith("# ")]
    m = re.match(r"bench/inplace\.sh on (.+) \((\w+)\)(?:, [^,]+)?, (\S+) \S+, (\d{4}-\d\d-\d\d), "
                 r"tree (\S+)$", comments[0])
    if m is None:
        raise ValueError("%s: its first line does not name the machine" % path)
    pairs = re.search(r"the median over (\d+) runs of each program", comments[3])
    facts = {"cpu": cpu_name(m.group(1)), "os": m.group(3), "date": m.group(4),
             "tree": m.group(5), "compiler": compiler_name(comments[1].split(";")[0]),
             "pairs": pairs.group(1) if pairs else "the"}
    data = [line for line in lines if line and not line.startswith("#")]
    return facts, list(csv.DictReader(data))


def compiler_name(text):
    """A compiler's name and version from the first line of its --version: gcc's last word,
    clang's word after "version", or the line itself."""
    if re.match(r"gcc(-\d+)? ", text):
        return "gcc " + text.split()[-1]
    m = re.search(r"clang version (\S+)", text)
    if m:
        return "clang " + m.group(1)
    return text


def size_label(bytes_text):
    n = int(bytes_text)
    if n < 1024:
        return "%d bytes" % n
    if n > 16384:
        return "%d KiB, %d records" % (n // 1024, n // 16384)
    return "%d KiB" % (n // 1024)


def speeds(rows, direction):
    """The section's rows as (label, [(speed, 25th, 75th percentile) of each AEAD]), in the CSV's
    order of sizes."""
    sizes = []
    speed = {}
    for row in rows:
        if row["direction"] != direction:
            continue
        if row["bytes"] not in sizes:
            sizes.append(row["bytes"])
        speed[(row["bytes"], row["aead"])] = (float(row["speed"]), float(row["speed_p25"]),
                                              float(row["speed_p75"]))
    return [(size_label(b), [speed.get((b, aead)) for aead, _, _ in AEADS]) for b in sizes]


def title_of(sections):
    """The title: the rows whose bar reads above 1.00x, as its label rounds it."""
    values = [v[0] for _, rows in sections for _, vs in rows for v in vs if v is not None]
    faster = sum(1 for v in values if round(v, 2) > 1)
    return "Reads and writes in place are faster than the copying calls in %d of %d rows" % (
        faster, len(values))


def description(facts, sections):
    text = ["On the %s under %s, %s. Each bar is the in-place call's speed in multiples of the "
            "copying call's." % (facts["cpu"], facts["compiler"], title_of(sections))]
    for (_, heading, _), (_, rows) in zip(SECTIONS, sections):
        text.append("%s: %s." % (heading, "; ".join(
            "%s %s" % (label, ", ".join("%s %.2fx (%.2f to %.2f)" % ((name,) + v)
                                        for (_, name, _), v in zip(AEADS, vs) if v is not None))
            for label, vs in rows)))
    return " ".join(text)


def header(parts, facts, sections, width, height):
    a = parts.append
    a('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" '
      'role="img" aria-labelledby="t d">' % (width, height, width, height))
    a('<title id="t">Reads and writes in place on the %s</title>' % escape(facts["cpu"]))
    a('<desc id="d">%s</desc>' % escape(description(facts, sections)))
    a(STYLE)
    a('<rect width="%d" height="%d" rx="8" fill="var(--surface)"/>' % (width, height))
    a('<text class="title" x="24" y="34">%s</text>' % escape(title_of(sections)))
    a('<text class="sub" x="24" y="56">Each bar is the in-place call\'s speed in multiples of '
      'the copying call\'s: the median over %s pairs of runs of the copying time over the '
      'in-place</text>' % facts["pairs"])
    a('<text class="sub" x="24" y="74">time. The whisker spans the 25th to the 75th percentile. '
      'A longer bar is faster.</text>')
    a('<text class="sub" x="24" y="92">%s, %s, %s, run on %s, tree %s.</text>'
      % (escape(facts["cpu"]), escape(facts["compiler"]), escape(facts["os"]), facts["date"],
         escape(facts["tree"])))
    a('<text class="sub" x="24" y="110">Copying: ch_read and ch_write over callbacks that copy, '
      'TRANSPORT=tcp-blocking.</text>')
    a('<text class="sub" x="24" y="128">In place: ch_read_in_place and ch_seal_in_place, '
      'TRANSPORT=tcp-nonblocking.</text>')
    legend_x = 24
    for _, name, fill in AEADS:
        a('<rect x="%d" y="144" width="12" height="12" rx="2" fill="var(%s)"/>' % (legend_x, fill))
        a('<text class="legend" x="%d" y="154">%s</text>' % (legend_x + 18, escape(name)))
        legend_x += 18 + 7 * len(name) + 24
    a('<line x1="%d" y1="150" x2="%d" y2="150" stroke="var(--unit)" stroke-width="1.5" '
      'stroke-dasharray="4 3"/>' % (legend_x, legend_x + 16))
    a('<text class="legend" x="%d" y="154">the copying call: the unit, 1×</text>'
      % (legend_x + 22))


def axis(parts, ox, sx, top, bottom, x_max):
    tick = 0.0
    while tick <= x_max + 1e-9:
        x = ox + sx(tick)
        parts.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="var(--grid)" '
                     'stroke-width="1"/>' % (x, top - 4, x, bottom + 4))
        parts.append('<text class="tick" x="%.1f" y="%d" text-anchor="middle">%g×</text>'
                     % (x, bottom + 18, tick))
        tick += 0.25


def whisker(parts, x1, x2, y):
    """A line from the 25th to the 75th percentile, with a short end at each."""
    parts.append('<path class="whisker" d="M%.1f,%.1f H%.1f M%.1f,%.1f v6 M%.1f,%.1f v6" '
                 'fill="none"/>' % (x1, y, x2, x1, y - 3, x2, y - 3))


def section_rows(parts, rows, ox, sx, y, geometry):
    bar_h, bar_gap, group_h, group_gap = geometry
    for label, values in rows:
        parts.append('<text class="row" x="%d" y="%.1f" text-anchor="end">%s</text>'
                     % (ox - 10, y + group_h / 2 + 4, escape(label)))
        for k, ((_, _, fill), v) in enumerate(zip(AEADS, values)):
            by = y + k * (bar_h + bar_gap)
            if v is None:
                parts.append('<text class="val" x="%.1f" y="%d">absent</text>'
                             % (ox + 6, by + bar_h - 1))
                continue
            w = max(sx(v[0]), 1)
            parts.append(bar(ox, by, w, bar_h, fill))
            whisker(parts, ox + sx(v[1]), ox + sx(v[2]), by + bar_h / 2)
            parts.append('<text class="val" x="%.1f" y="%d">%.2f×</text>'
                         % (ox + max(w, sx(v[2])) + 5, by + bar_h - 1, v[0]))
        y += group_h + group_gap
    return y


def draw(path):
    """One chart's SVG text."""
    facts, rows = read_run(path)
    sections = [(direction, speeds(rows, direction)) for direction, _, _ in SECTIONS]
    width, label_w, section_h = 960, 200, 30
    bar_h, bar_gap, group_gap = 10, 2, 10
    group_h = len(AEADS) * bar_h + (len(AEADS) - 1) * bar_gap
    present = [v[2] for _, rs in sections for _, vs in rs for v in vs if v is not None]
    x_max = max(1.5, math.ceil(max(present, default=1) * 4) / 4)
    plot_w = width - 24 - label_w - 72
    top = 182
    rows_h = sum(section_h + len(rs) * (group_h + group_gap) for _, rs in sections)
    height = top + rows_h + 40

    def sx(v):
        return v / x_max * plot_w

    ox = 24 + label_w
    parts = []
    header(parts, facts, sections, width, height)
    bottom = top + rows_h - group_gap
    axis(parts, ox, sx, top, bottom, x_max)
    y = top
    for (_, heading, unit), (_, rs) in zip(SECTIONS, sections):
        parts.append('<text class="section" x="24" y="%d">%s</text>' % (y + section_h - 11,
                                                                         escape(heading)))
        parts.append('<text class="row" x="%d" y="%d" text-anchor="end">%s</text>'
                     % (width - 24, y + section_h - 11, escape(unit)))
        y = section_rows(parts, rs, ox, sx, y + section_h, (bar_h, bar_gap, group_h, group_gap))
    x1 = ox + sx(1)
    parts.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="var(--unit)" '
                 'stroke-width="1.5" stroke-dasharray="4 3"/>' % (x1, top - 8, x1, bottom + 4))
    parts.append('</svg>')
    return "\n".join(parts) + "\n"


def check_charts():
    """Each CSV's committed chart against what this file draws, an SVG with no CSV, and
    docs/performance.md's image line for each chart."""
    rc = 0
    csvs = sorted(glob.glob(CSV_GLOB))
    want = {chart_path(p): p for p in csvs}
    doc = open(DOC).read()
    for svg in sorted(glob.glob("%s/inplace-*.svg" % IMG)):
        if svg not in want:
            print("lint-bench-numbers: %s has no CSV in bench/; delete it" % svg)
            rc = 1
    for svg, path in sorted(want.items()):
        try:
            got = open(svg).read()
        except OSError:
            got = None
        if got != draw(path):
            print("lint-bench-numbers: %s is not what tools/inplace_chart.py draws from %s; run "
                  "python3 tools/inplace_chart.py and commit the SVGs" % (svg, path))
            rc = 1
        if "(img/%s)" % os.path.basename(svg) not in doc:
            print("lint-bench-numbers: %s does not show %s" % (DOC, svg))
            rc = 1
    return rc


def main():
    for path in sorted(glob.glob(CSV_GLOB)):
        svg = chart_path(path)
        with open(svg, "w") as f:
            f.write(draw(path))
        print("wrote %s" % svg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
