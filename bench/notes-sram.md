# Memory: how the measured peaks changed

This note holds the history of the figures that docs/performance.md,
"Memory", shows from bench/results-sram.csv, which bench/sram.sh writes.
It moved from that page on 2026-11-27.

## Peak stack

Two rows of docs/performance.md's peak stack table grew in October 2026, and `bench/stack.py` names the
frame each time:

- `ch_read`, 1,872 to 1,888 bytes. `io_read_record` names the alert its
  caller sends through a pointer (docs/decisions.md 166). `ch_read`
  inlines the call, so the alert is a byte in `ch_read`'s own frame, and
  arm64 rounds the frame from 96 to 112 bytes. Every frame below it is
  the same.
- `ch_write`, 1,520 to 1,616 bytes. `ch_write` is `ch_write_parts` over
  one part (docs/decisions.md 167), so the KeyUpdate path runs under one
  more frame, 96 bytes.

One more grew in November 2026:

- `ch_close`, 880 to 1,072 bytes. The close_notify record's seal keys
  Poly1305 through `chacha20_block`, which then wipes 512 bytes of the
  stack below it, `wipe_frame`'s array (docs/decisions.md 229). Before
  it, the deepest chain ran through Poly1305's blocks.
