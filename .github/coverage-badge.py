#!/usr/bin/env python3
"""Render a flat coverage badge as SVG from gcovr's JSON summary.

Usage: coverage-badge.py bin/coverage.json > .github/badges/coverage.svg

Self-contained on purpose: the repository takes no badge service or
third-party action for this. CI regenerates the SVG after make coverage
and commits it only when the number changed.
"""

import json
import sys

pct = json.load(open(sys.argv[1]))["line_percent"]
label = "coverage"
value = f"{pct:.1f}%"
# Green at or above 90, yellow above 75, red below: the same bands the
# gcovr report uses.
color = "#4c1" if pct >= 90 else "#dfb317" if pct > 75 else "#e05d44"
# Widths sized for the fixed-width label and a 5-character value at
# Verdana 11px, the geometry every badge service uses.
lw, vw = 61, 46
svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{lw + vw}" height="20" role="img" aria-label="{label}: {value}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{lw + vw}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="#555"/>
    <rect x="{lw}" width="{vw}" height="20" fill="{color}"/>
    <rect width="{lw + vw}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw / 2:.0f}" y="14">{label}</text>
    <text x="{lw + vw / 2:.0f}" y="14">{value}</text>
  </g>
</svg>
"""
sys.stdout.write(svg)
