#!/usr/bin/env python3
"""Draws docs/img/speed-vs-openssl-*.svg: chapulin's speed beside OpenSSL's on each CPU of
docs/performance.md's table "chapulin beside OpenSSL".

    python3 tools/speed_chart.py

The charts read the CSVs that table reads, through tools/bench_scoreboard.py's own functions, so
a chart and the table pick the same rows: the widest ch_cfg.cpu value a CSV holds for chapulin,
and OpenSSL's row of the same run. Each bar is chapulin's speed in multiples of OpenSSL's, which
is OpenSSL's time over chapulin's: the inverse of the table's ratio. A row whose OpenSSL cell
times another operation has no ratio in the table and no bar here. One chart holds one CPU, and
a Linux CPU's chart holds a bar for each of the two compilers the table holds.

tools/bench-numbers.py calls check_charts, so `make lint-bench-numbers` fails when a committed
SVG is not what this file draws from the CSVs. After a run moves a CSV, run this file and commit
its SVGs with the CSVs. It also adds the run to bench/history-speed-vs-openssl.csv and draws
docs/img/speed-history-*.svg (tools/speed_history.py). The output holds no date and no time of its own, so the same CSVs draw
the same bytes.
"""
import math
import re
import sys

from bench_scoreboard import (AEADS, MACHINES, PRIMITIVES, facts, openssl_row, primitive_ns,
                              primitive_row, read_csv, record_ns, record_row, widest)

# One chart for each CPU: the file's name, and the table's column groups the chart draws, in
# the order of their bars. Each group's name is a name in bench_scoreboard.MACHINES.
CHARTS = [
    ("m1-pro", ["M1 Pro"]),
    ("x86-64", ["x86-64 gcc", "x86-64 clang"]),
    ("x86-64-avx512", ["x86-64 AVX-512 gcc", "x86-64 AVX-512 clang"]),
    ("arm64", ["arm64 gcc", "arm64 clang"]),
]

IMG = "docs/img"

# The heading over each run of rows, by the first row it holds.
SECTIONS = {
    "SHA-256, 16 KiB": "Hashes",
    "X25519 key generation": "Key exchange",
    "ECDSA P-256 sign": "Signatures",
    "ML-KEM-768 key generation": "Post-quantum",
    "AES-128-GCM, the key set and one 16 KiB record sealed": "Records",
}

# The bar colors, one CSS variable for each bar of a row.
FILLS = ["--first", "--second"]


def chart_path(slug):
    return "%s/speed-vs-openssl-%s.svg" % (IMG, slug)


def compiler_name(text):
    """A compiler's name and version from a CSV's second comment line."""
    if text.startswith("gcc "):
        return "gcc " + text.split()[-1]
    m = re.match(r"(Apple |Ubuntu )?clang version (\S+)", text)
    if m:
        return ("Apple clang " if m.group(1) == "Apple " else "clang ") + m.group(2)
    return text.split(";")[0]


def speeds(primitives, record):
    """Each row the chart draws, as its label and chapulin's speed in multiples of OpenSSL's,
    or None where either time is absent."""
    rows = [] if primitives is None else primitives[1]
    out = []
    for label, ours_name, theirs_name, size, *other in PRIMITIVES:
        if other:
            continue
        ours = primitive_ns(widest(rows, primitive_row(ours_name, size)))
        theirs = primitive_ns(openssl_row(rows, primitive_row(theirs_name, size)))
        out.append((label, theirs / ours if ours and theirs else None))
    rows = [] if record is None else record[1]
    for label, aead, stage in AEADS:
        ours = record_ns(widest(rows, record_row(aead, stage)))
        theirs = record_ns(openssl_row(rows, record_row(aead, "openssl_" + stage)))
        out.append((label, theirs / ours if ours and theirs else None))
    return out


def series(names):
    """For each column group: its compiler, its facts and its speeds."""
    by_name = {name: (primitives, record) for name, primitives, record in MACHINES}
    out = []
    for name in names:
        primitives, record = (read_csv(path) for path in by_name[name])
        known = facts(*primitives) if primitives else None
        out.append((compiler_name(known["compiler"]) if known else name, known,
                    speeds(primitives, record)))
    return out


def claim(values, compiler, first):
    """How many rows one compiler's chapulin runs faster than OpenSSL. The title names the
    compiler's family, and the legend its version."""
    present = [v for v in values if v is not None]
    faster = sum(1 for v in present if v > 1)
    return "%d of %d %sunder %s" % (faster, len(present), "rows " if first else "",
                                     compiler.rsplit(" ", 1)[0])


def bar(x, y, width, height, fill):
    """A bar with a rounded data end, square at the baseline."""
    radius = min(3, width / 2)
    return ('<path d="M%.1f,%.1f h%.1f a%.1f,%.1f 0 0 1 %.1f,%.1f v%.1f a%.1f,%.1f 0 0 1 %.1f,%.1f '
            'h%.1f z" fill="var(%s)"/>'
            % (x, y, width - radius, radius, radius, radius, radius, height - 2 * radius, radius,
               radius, -radius, radius, -(width - radius), fill))


def escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def title_of(drawn, openssl):
    """A chart's title: the rows where each compiler's chapulin runs faster than OpenSSL."""
    return "chapulin is faster than %s in %s" % (
        openssl, " and ".join(claim([v for _, v in s], c, k == 0)
                              for k, (c, _, s) in enumerate(drawn)))


def cpu_name(text):
    """A CPU's name as the README writes it: the CSV's name without trademark signs or a core
    count, and in title case where the CSV writes it in capitals."""
    text = re.sub(r"\((R|TM)\)", "", text)
    capitals = text.isupper()
    text = re.sub(r"\s+\d+-Core Processor$", "", text)
    text = " ".join(text.split())
    if capitals:
        text = " ".join(w if any(ch.isdigit() for ch in w) else w.capitalize()
                        for w in text.split())
    return text


def headline(names):
    """The README's sentence for one chart: its CPU and its title."""
    drawn = series(names)
    known = next((f for _, f, _ in drawn if f), None)
    if known is None:
        return None
    return "%s: %s" % (cpu_name(known["cpu"]), title_of(drawn, known["openssl"]))


def draw(names):
    """One chart's SVG text."""
    drawn = series(names)
    known = next((f for _, f, _ in drawn if f), None)
    labels = [label for label, _ in drawn[0][2]]
    cpu = known["cpu"] if known else names[0]
    openssl = known["openssl"] if known else "OpenSSL"
    title = title_of(drawn, openssl)

    width = 960
    pad_l = 24
    label_w = 372
    plot_w = width - pad_l - label_w - 72
    bar_h, bar_gap, group_gap, section_h = 10, 2, 8, 26
    group_h = len(drawn) * bar_h + (len(drawn) - 1) * bar_gap
    present = [v for _, _, s in drawn for _, v in s if v is not None]
    x_max = max(2, math.ceil(max(present, default=1) * 2) / 2)
    tick_step = 0.5 if x_max <= 3 else 1
    top = 146
    rows_h = sum(group_h + group_gap + (section_h if label in SECTIONS else 0)
                 for label in labels)
    height = top + rows_h + 40

    def sx(v):
        return v / x_max * plot_w

    ox = pad_l + label_w
    parts = []
    a = parts.append
    a('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" '
      'role="img" aria-labelledby="t d">' % (width, height, width, height))
    a('<title id="t">chapulin beside %s on the %s</title>' % (escape(openssl), escape(cpu)))
    desc = ["On the %s, %s. Each bar is chapulin's speed in multiples of %s's: %s's time over chapulin's, "
            "on the same machine in the same run." % (cpu, title, openssl, openssl)]
    for compiler, _, values in drawn:
        desc.append("Under %s: %s." % (compiler, "; ".join(
            "%s %s" % (label, "absent" if v is None else "%.2fx" % v) for label, v in values)))
    a('<desc id="d">%s</desc>' % escape(" ".join(desc)))
    a('''<style>
svg { --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#8a8984; --grid:#e4e3df; --first:#2a78d6; --second:#eb6834; --unit:#52514e; }
@media (prefers-color-scheme: dark) {
  svg { --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --muted:#8f8e86; --grid:#33332f; --first:#3987e5; --second:#d95926; --unit:#c3c2b7; }
}
text { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: var(--ink); }
.title { font-size: 17px; font-weight: 600; }
.sub { font-size: 12.5px; fill: var(--ink2); }
.section { font-size: 13.5px; font-weight: 600; }
.row { font-size: 12.5px; fill: var(--ink2); }
.val { font-size: 10.5px; font-weight: 600; paint-order: stroke; stroke: var(--surface); stroke-width: 3px; stroke-linejoin: round; }
.tick { font-size: 11px; fill: var(--muted); }
.legend { font-size: 12.5px; fill: var(--ink2); }
</style>''')
    a('<rect width="%d" height="%d" rx="8" fill="var(--surface)"/>' % (width, height))
    a('<text class="title" x="%d" y="34">%s</text>' % (pad_l, escape(title)))
    a('<text class="sub" x="%d" y="56">Each bar is chapulin\'s speed in multiples of %s\'s: '
      '%s\'s time over chapulin\'s, on the same machine in the same run. A longer bar is '
      'faster.</text>' % (pad_l, escape(openssl), escape(openssl)))
    if known:
        a('<text class="sub" x="%d" y="74">%s, %s, run on %s, tree %s.</text>'
          % (pad_l, escape(cpu), escape(known["os"]), known["date"], escape(known["tree"])))
    a('<text class="sub" x="%d" y="92">chapulin runs under the widest ch_cfg.cpu value each CSV '
      'holds, as docs/performance.md\'s table does.</text>' % pad_l)
    legend_y = 118
    legend_x = pad_l
    for (compiler, _, _), fill in zip(drawn, FILLS):
        name = "chapulin, %s" % compiler
        a('<rect x="%d" y="%d" width="12" height="12" rx="2" fill="var(%s)"/>'
          % (legend_x, legend_y - 10, fill))
        a('<text class="legend" x="%d" y="%d">%s</text>' % (legend_x + 18, legend_y, escape(name)))
        legend_x += 18 + 7 * len(name) + 24
    a('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="var(--unit)" stroke-width="1.5" '
      'stroke-dasharray="4 3"/>' % (legend_x, legend_y - 4, legend_x + 16, legend_y - 4))
    a('<text class="legend" x="%d" y="%d">%s: the unit, 1×</text>'
      % (legend_x + 22, legend_y, escape(openssl)))

    bottom = top + rows_h - group_gap
    tick = 0.0
    while tick <= x_max + 1e-9:
        x = ox + sx(tick)
        a('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="var(--grid)" stroke-width="1"/>'
          % (x, top - 4, x, bottom + 4))
        a('<text class="tick" x="%.1f" y="%d" text-anchor="middle">%g×</text>'
          % (x, bottom + 18, tick))
        tick += tick_step
    y = top
    for i, label in enumerate(labels):
        if label in SECTIONS:
            a('<text class="section" x="%d" y="%d">%s</text>'
              % (pad_l, y + section_h - 9, SECTIONS[label]))
            y += section_h
        a('<text class="row" x="%d" y="%.1f" text-anchor="end">%s</text>'
          % (ox - 10, y + group_h / 2 + 4, escape(label)))
        for k, ((_, _, values), fill) in enumerate(zip(drawn, FILLS)):
            by = y + k * (bar_h + bar_gap)
            v = values[i][1]
            if v is None:
                a('<text class="val" x="%.1f" y="%d">absent</text>' % (ox + 6, by + bar_h - 1))
                continue
            w = max(sx(v), 1)
            a(bar(ox, by, w, bar_h, fill))
            a('<text class="val" x="%.1f" y="%d">%.2f×</text>' % (ox + w + 5, by + bar_h - 1, v))
        y += group_h + group_gap
    x1 = ox + sx(1)
    a('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="var(--unit)" stroke-width="1.5" '
      'stroke-dasharray="4 3"/>' % (x1, top - 8, x1, bottom + 4))
    a('</svg>')
    return "\n".join(parts) + "\n"


def check_charts():
    """Each committed chart against what this file draws from the CSVs, and the README's
    sentence for each chart: its CPU and its title, in the "Performance" section's first line
    or in a <summary> line."""
    rc = 0
    readme = " ".join(open("README.md").read().split())
    for slug, names in CHARTS:
        want = headline(names)
        if want is not None and want not in readme:
            print("lint-bench-numbers: README.md does not state %r, which the CSVs give for "
                  "%s" % (want, chart_path(slug)))
            rc = 1
    for slug, names in CHARTS:
        path = chart_path(slug)
        want = draw(names)
        try:
            got = open(path).read()
        except OSError:
            got = None
        if got != want:
            print("lint-bench-numbers: %s is not what tools/speed_chart.py draws from the CSVs; "
                  "run python3 tools/speed_chart.py and commit the SVGs" % path)
            rc = 1
    return rc


def main():
    for slug, names in CHARTS:
        path = chart_path(slug)
        with open(path, "w") as f:
            f.write(draw(names))
        print("wrote %s" % path)
    # The history reads this file's speeds, so it is imported here and not at the top.
    import speed_history
    for name in speed_history.record():
        print("added a point for %s to %s" % (name, speed_history.HISTORY))
    speed_history.draw_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
