#!/usr/bin/env python3
"""Keeps bench/history-speed-vs-openssl.csv and draws docs/img/speed-history-*.svg: chapulin's
speed beside OpenSSL's on each CPU, for each recording of the table "chapulin beside OpenSSL".

    python3 tools/speed_chart.py              adds a point for each column a run moved, and
                                              draws the bars and these charts
    python3 tools/speed_history.py --backfill writes the history again from git's commits of
                                              the CSVs (a local clone with its whole history)

A point is one column group's speeds, as tools/speed_chart.py computes them: OpenSSL's time over
chapulin's for each row. A group's next point is written when its CSVs state another run, or
when a row's speed moved, so a run that records a few rows again makes a point too. The history
keeps the CPU each run states, and a chart draws the points of its CPU alone: an x-86-64 CSV
could come from another CPU model before the bench workflow checked which kind it drew.

tools/bench-numbers.py calls check_history, so `make lint-bench-numbers` fails when a group's
last point is not what its CSVs give now, or when a committed chart is not what this file draws.
"""
import csv
import io
import subprocess
import sys

from bench_scoreboard import MACHINES, facts, parse_csv, read_csv
from speed_chart import CHARTS, FILLS, IMG, escape, speeds

HISTORY = "bench/history-speed-vs-openssl.csv"
COLUMNS = ["group", "point", "cpu", "date", "tree", "row", "speed"]
HEAD = ("# chapulin's speed beside OpenSSL on each column group of docs/performance-openssl.md's "
        "table:\n"
        "# OpenSSL's time over chapulin's, one point for each run tools/speed_history.py saw.\n"
        "# tools/speed_chart.py adds the points, and make lint-bench-numbers checks the last.\n")


def state(primitives, record):
    """A group's point from its two parsed CSVs: the CPU, the date and the tree the primitives
    CSV states, and each row's speed as text, or None when the primitives CSV is absent."""
    if primitives is None:
        return None
    known = facts(*primitives)
    rows = [(label, "" if v is None else "%.3f" % v) for label, v in speeds(primitives, record)]
    return known["cpu"], known["date"], known["tree"], rows


def read_history():
    """Each group's points, in order, as (point, cpu, date, tree, rows)."""
    points = {}
    try:
        text = open(HISTORY).read()
    except OSError:
        return points
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    for r in csv.DictReader(lines):
        group = points.setdefault(r["group"], [])
        key = int(r["point"])
        if not group or group[-1][0] != key:
            group.append((key, r["cpu"], r["date"], r["tree"], []))
        group[-1][4].append((r["row"], r["speed"]))
    return points


def write_history(points):
    out = io.StringIO()
    out.write(HEAD)
    w = csv.writer(out, lineterminator="\n")
    w.writerow(COLUMNS)
    for name, _, _ in MACHINES:
        for key, cpu, date, tree, rows in points.get(name, []):
            for row, speed in rows:
                w.writerow([name, key, cpu, date, tree, row, speed])
    with open(HISTORY, "w") as f:
        f.write(out.getvalue())


def add(points, name, now):
    """Adds now as the group's next point when it differs from the last. True when it did."""
    if now is None:
        return False
    group = points.setdefault(name, [])
    if group and group[-1][1:] == now:
        return False
    group.append((group[-1][0] + 1 if group else 1,) + now)
    return True


def current():
    return {name: state(read_csv(p), read_csv(r)) for name, p, r in MACHINES}


def record():
    """Adds a point for each group whose CSVs moved. The names of those groups."""
    points = read_history()
    moved = [name for name, now in current().items() if add(points, name, now)]
    if moved:
        write_history(points)
    return moved


def git(*args):
    return subprocess.run(["git"] + list(args), check=True, capture_output=True,
                          text=True).stdout


def at(commit, path):
    """A CSV parsed from one commit, or None where the commit holds no such file."""
    try:
        return parse_csv(git("show", "%s:%s" % (commit, path)))
    except subprocess.CalledProcessError:
        return None


def backfill():
    """Writes the history again from each commit that changed a group's CSVs, oldest first."""
    points = {}
    for name, p, r in MACHINES:
        for commit in git("log", "--reverse", "--format=%H", "HEAD", "--", p, r).split():
            try:
                now = state(at(commit, p), at(commit, r))
            except (KeyError, ValueError, AttributeError, StopIteration):
                print("speed_history: %s at %s does not parse; skipped" % (name, commit[:8]))
                continue
            add(points, name, now)
        add(points, name, current()[name])
    write_history(points)
    for name, _, _ in MACHINES:
        print("speed_history: %s, %d points" % (name, len(points.get(name, []))))


def history_path(slug):
    return "%s/speed-history-%s.svg" % (IMG, slug)


def chart_series(points, names):
    """For each group of a chart: its points on the CPU its last point states, one for each
    date, the last of that date."""
    out = []
    for name in names:
        group = points.get(name, [])
        cpu = group[-1][1] if group else None
        by_date = {}
        for _, p_cpu, date, _, rows in group:
            if p_cpu == cpu:
                by_date[date] = dict(rows)
        out.append((name, cpu, sorted(by_date.items())))
    return out


def draw(names):
    """One CPU's chart: a panel for each row, a line for each group, over the dates."""
    drawn = chart_series(read_history(), names)
    cpu = next((c for _, c, _ in drawn if c), names[0])
    dates = sorted({d for _, _, pts in drawn for d, _ in pts})
    labels = [row for row, _ in read_history()[names[0]][-1][4]] if drawn[0][2] else []
    width, pad_l, cols = 960, 24, 3
    gap = 18
    panel_w = (width - 2 * pad_l - (cols - 1) * gap) / cols
    panel_h, plot_h = 96, 56
    top = 132
    rows_of_panels = (len(labels) + cols - 1) // cols
    height = top + rows_of_panels * panel_h + 24

    def day(d):
        y, m, dd = (int(x) for x in d.split("-"))
        return y * 372 + m * 31 + dd

    first, last = (day(dates[0]), day(dates[-1])) if dates else (0, 1)
    span = max(last - first, 1)

    parts = []
    a = parts.append
    a('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" '
      'role="img" aria-labelledby="t d">' % (width, height, width, height))
    a('<title id="t">chapulin\'s speed beside OpenSSL over time on the %s</title>' % escape(cpu))
    desc = []
    for name, _, pts in drawn:
        desc.append("%s: runs on %d days, from %s to %s." % (
            name, len(pts), pts[0][0] if pts else "none", pts[-1][0] if pts else "none"))
    a('<desc id="d">Each panel is one row of docs/performance-openssl.md\'s table beside OpenSSL. '
      'A line '
      'is chapulin\'s speed in multiples of OpenSSL\'s at each recording. %s</desc>'
      % escape(" ".join(desc)))
    a('''<style>
svg { --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#8a8984; --grid:#e4e3df; --first:#2a78d6; --second:#eb6834; --unit:#52514e; }
@media (prefers-color-scheme: dark) {
  svg { --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --muted:#8f8e86; --grid:#33332f; --first:#3987e5; --second:#d95926; --unit:#c3c2b7; }
}
text { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: var(--ink); }
.title { font-size: 17px; font-weight: 600; }
.sub { font-size: 12.5px; fill: var(--ink2); }
.panel { font-size: 11.5px; font-weight: 600; }
.val { font-size: 10px; font-weight: 600; }
.legend { font-size: 12.5px; fill: var(--ink2); }
</style>''')
    a('<rect width="%d" height="%d" rx="8" fill="var(--surface)"/>' % (width, height))
    a('<text class="title" x="%d" y="34">chapulin\'s speed beside OpenSSL at each recording</text>'
      % pad_l)
    a('<text class="sub" x="%d" y="56">%s, from %s to %s. A point above the dashed line at 1 is a '
      'run where chapulin was faster.</text>' % (pad_l, escape(cpu), dates[0] if dates else "-",
                                                 dates[-1] if dates else "-"))
    a('<text class="sub" x="%d" y="74">Each panel has its own scale. A line draws the last run of '
      'each day, and the number at its right is the last run\'s speed.</text>' % pad_l)
    legend_x = pad_l
    for (name, _, pts), fill in zip(drawn, FILLS):
        text = "%s, runs on %d days" % (name, len(pts))
        a('<rect x="%d" y="%d" width="12" height="12" rx="2" fill="var(%s)"/>'
          % (legend_x, 92, fill))
        a('<text class="legend" x="%d" y="102">%s</text>' % (legend_x + 18, escape(text)))
        legend_x += 18 + 7 * len(text) + 24
    for i, label in enumerate(labels):
        px = pad_l + (i % cols) * (panel_w + gap)
        py = top + (i // cols) * panel_h
        a('<text class="panel" x="%.1f" y="%d">%s</text>' % (px, py + 12, escape(label)))
        values = [float(r[label]) for _, _, pts in drawn for _, r in pts if r.get(label)]
        lo = min(values + [1.0]) * 0.95
        hi = max(values + [1.0]) * 1.05
        plot_w = panel_w - 44
        oy = py + 20

        def sy(v):
            return oy + plot_h - (v - lo) / (hi - lo) * plot_h

        a('<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="none" stroke="var(--grid)"/>'
          % (px, oy, plot_w, plot_h))
        a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="var(--unit)" stroke-width="1" '
          'stroke-dasharray="3 3"/>' % (px, sy(1), px + plot_w, sy(1)))
        for k, ((_, _, pts), fill) in enumerate(zip(drawn, FILLS)):
            xy = [(px + (day(d) - first) / span * plot_w, sy(float(r[label])))
                  for d, r in pts if r.get(label)]
            if not xy:
                continue
            if len(xy) > 1:
                a('<polyline points="%s" fill="none" stroke="var(%s)" stroke-width="1.5"/>'
                  % (" ".join("%.1f,%.1f" % p for p in xy), fill))
            a('<circle cx="%.1f" cy="%.1f" r="2.2" fill="var(%s)"/>' % (xy[-1] + (fill,)))
            last_v = [float(r[label]) for _, r in pts if r.get(label)][-1]
            a('<text class="val" x="%.1f" y="%.1f" style="fill:var(%s)">%.2f×</text>'
              % (px + plot_w + 4, oy + 12 + 14 * k, fill, last_v))
    a('</svg>')
    return "\n".join(parts) + "\n"


def draw_all():
    for slug, names in CHARTS:
        with open(history_path(slug), "w") as f:
            f.write(draw(names))


def check_history():
    """Each group's last point against its CSVs, and each chart against what this file draws."""
    rc = 0
    points = read_history()
    for name, now in current().items():
        group = points.get(name)
        if now is not None and (not group or group[-1][1:] != now):
            print("lint-bench-numbers: %s's last point in %s is not what its CSVs give; run "
                  "python3 tools/speed_chart.py and commit the history" % (name, HISTORY))
            rc = 1
    for slug, names in CHARTS:
        path = history_path(slug)
        try:
            got = open(path).read()
        except OSError:
            got = None
        if got != draw(names):
            print("lint-bench-numbers: %s is not what tools/speed_history.py draws from %s; "
                  "run python3 tools/speed_chart.py and commit the SVGs" % (path, HISTORY))
            rc = 1
    return rc


def main():
    if sys.argv[1:] == ["--backfill"]:
        backfill()
    else:
        for name in record():
            print("speed_history: a point for %s" % name)
    draw_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
