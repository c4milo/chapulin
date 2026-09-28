/-!
How much plaintext one `ch_write` seals into `cap` bytes of records:
`ch_writable_len` in `tls_write.c`, and the two helpers it calls, `records_fill`
and `fill_across_key_update`. Each definition here is one C function over
`Nat`, with one `let` for each C local in the order the C computes them, so a
reader can check each line against `tls_write.c`.

The C computes on `size_t`, which is 32 bits on the target devices and 64 bits
on a host. An unsigned sum or product whose exact value is below `2^w` keeps
that value in a `size_t` of `w` bits (C11 §6.2.5). `recordsFill_fits` and
`fillAcrossKeyUpdate_fits` prove that every sum and product the C computes is
below `2^w`, for every width `w` of 15 bits or more, every `cap` below `2^w`
and every `limit` from 1 to 16384. So at every such width each C operation
gives the value the matching `let` here gives, and `writableLen_le_cap` proves
that the answer is at most `cap`. C11 §7.20.3 sets the least `SIZE_MAX` at 65535, so every
`size_t` has 16 bits or more. 15 bits is the least width the proofs need:
`limit + REC_OVERHEAD` is 16406 at the largest `limit`, and 16406 needs 15
bits.

The model takes these facts from the C, which `tls_write.c`, `cfg.h`,
`ct.h` and `record.h` state:

- `record_plaintext_max` answers the smaller of `peer_limit` and `CH_TX_PT`,
  and `cfg.h` asserts that `CH_TX_PT` is 512 to 16384. So `limit` is at most
  16384.
- `ch_writable_len` returns 0 when `limit` is 0, before `records_fill`
  divides. So every division here is by 23 or more.
- `records_before_key_update` gives `room`. Under AES-GCM it computes
  `last - seq` in `uint64_t` when `seq < last`, where `last` is
  `REC_AES_GCM_RECORDS_MAX - 1`, and answers 0 otherwise. So `room` is 0 to
  2^24 - 1, which a `size_t` of 24 bits or more holds unchanged, and
  `ct.h` refuses any build whose `size_t` has fewer than 32 bits. Under
  ChaCha20-Poly1305 it answers `SIZE_MAX`. Every theorem here takes any
  `room`, so none of them depends on what the cast to `size_t` keeps.
- A build without `-DCH_SUITE_AES_GCM` has no `room` and no
  `fill_across_key_update`, and returns what `records_fill` returns.
  `writableLen_of_cap_le_room` proves that `writableLen` returns the same for
  every `room` of `cap` or more, and `SIZE_MAX` is such a `room`.

This module is written from the C, not from an RFC, and CONTRACT.md says why.
`test/diff_writable_len.h` compares `writableLen` with the C's
`ch_writable_len` in `bin/diff` and, under `SUITE=aesgcm`, in
`bin/diff_webpki_aes`.
-/
namespace Spec.TlsWrite

/-- `REC_OVERHEAD` (`record.h`): the 22 bytes one sealed record adds to its
plaintext, the 5-byte header, the inner content type and the 16-byte AEAD tag
(RFC 9846 §5.2). -/
def recOverhead : Nat := 22

/-- `CH_KEY_UPDATE_RECORD_LEN` (`tls.h`): the 27 bytes of one sealed KeyUpdate
record, `REC_OVERHEAD`, the 4-byte handshake header and the 1-byte
request_update (RFC 9846 §4.7.3). -/
def keyUpdateRecordLen : Nat := 27

/-- `REC_AES_GCM_RECORDS_MAX` (`record.h`): the most records one AES-GCM write
key seals, 2^24. `ch_write` sends the KeyUpdate record at the last of them, so
a key seals at most `REC_AES_GCM_RECORDS_MAX - 1` data records. -/
def aesGcmRecordsMax : Nat := 16777216

/-- The largest `CH_TX_PT` that `cfg.h` admits, 16384, the most plaintext RFC
9846 §5.1 lets one record carry (docs/decisions.md 71). -/
def txPtMax : Nat := 16384

/-- What `records_fill` computes for one `cap` and one `limit`: its four
locals, under the C's names, and its two results. -/
structure RecordsFill where
  /-- `whole`: how many whole records, of `limit` bytes of plaintext each, `cap`
  holds. -/
  whole : Nat
  /-- `in_whole`: the plaintext of those whole records. -/
  inWhole : Nat
  /-- `overhead`: the overhead of `whole + 1` records. -/
  overhead : Nat
  /-- `with_one_more`: what `cap` holds for plaintext after that overhead, or 0. -/
  withOneMore : Nat
  /-- `*records`: how many records `ch_write` sends `fill` in. -/
  records : Nat
  /-- The return value: the most plaintext `cap` bytes of records carry. -/
  fill : Nat

/-- `records_fill (cap, limit, &records)`: the most plaintext that `cap` bytes
of records carry at `limit` bytes of plaintext per record, and how many
records that is. -/
def recordsFill (cap limit : Nat) : RecordsFill :=
  let whole := cap / (limit + recOverhead)
  let inWhole := whole * limit
  let overhead := (whole + 1) * recOverhead
  let withOneMore := if cap > overhead then cap - overhead else 0
  if withOneMore > inWhole then
    { whole, inWhole, overhead, withOneMore, records := whole + 1, fill := withOneMore }
  else
    { whole, inWhole, overhead, withOneMore, records := whole, fill := inWhole }

/-- What `fill_across_key_update` computes for one `cap`, `limit` and `room`:
its four locals, under the C's names, and its result. -/
structure FillAcross where
  /-- `left`: what `cap` holds after `room` whole records. -/
  left : Nat
  /-- `rest`: what `left` holds after the KeyUpdate record, or 0. -/
  rest : Nat
  /-- `records`: how many records `records_fill` counts in `rest`. -/
  records : Nat
  /-- `after`: the plaintext of those records, cut to
  `REC_AES_GCM_RECORDS_MAX - 1` records when there are more. -/
  after : Nat
  /-- The return value, `room * limit + after`. -/
  fill : Nat

/-- `fill_across_key_update (cap, limit, room)`: the most plaintext `cap` bytes
carry when `ch_write` sends `room` whole records under the current key, then
the KeyUpdate record, then the rest under the next key. `ch_writable_len`
calls it only when `room` is below the count `records_fill` returns for `cap`.
`cap - room * (limit + REC_OVERHEAD)` stops at 0 here where the C's would
wrap, and `fillAcrossKeyUpdate_fits` proves that the product is at most `cap`
at every call, so the two agree there. -/
def fillAcrossKeyUpdate (cap limit room : Nat) : FillAcross :=
  let left := cap - room * (limit + recOverhead)
  let rest := if left > keyUpdateRecordLen then left - keyUpdateRecordLen else 0
  let records := (recordsFill rest limit).records
  let after :=
    if records > aesGcmRecordsMax - 1 then (aesGcmRecordsMax - 1) * limit
    else (recordsFill rest limit).fill
  { left, rest, records, after, fill := room * limit + after }

/-- `ch_writable_len (t, cap)`, where `limit` is what `record_plaintext_max (t)`
answers and `room` is what `records_before_key_update (t)` answers. A build
without `-DCH_SUITE_AES_GCM` has no `room`, and `SIZE_MAX` stands for it
(`writableLen_of_cap_le_room`). -/
def writableLen (cap limit room : Nat) : Nat :=
  if limit = 0 then 0
  else
    let records := (recordsFill cap limit).records
    let fill := (recordsFill cap limit).fill
    if records > room then (fillAcrossKeyUpdate cap limit room).fill else fill

/-- `records_fill`'s count is `whole`, or `whole + 1` when one more record
carries a byte. -/
theorem recordsFill_records (cap limit : Nat) :
    (recordsFill cap limit).records = (recordsFill cap limit).whole ∨
      (recordsFill cap limit).records = (recordsFill cap limit).whole + 1 := by
  simp only [recordsFill]
  split <;> split <;> dsimp only <;> omega

/-- The whole records and their overhead fit `cap`: `records_fill`'s one
division, read back. -/
private theorem recordsFill_whole_mul_le (cap limit : Nat) :
    (recordsFill cap limit).whole * (limit + recOverhead) ≤ cap := by
  have h_quotient := Nat.div_mul_le_self cap (limit + recOverhead)
  simp only [recordsFill]
  split <;> split <;> exact h_quotient

/-- `records_fill`'s answer is at most `cap`: the records it counts fit. -/
theorem recordsFill_fill_le (cap limit : Nat) : (recordsFill cap limit).fill ≤ cap := by
  have h_quotient := Nat.div_mul_le_self cap (limit + recOverhead)
  have h_product := Nat.mul_add (cap / (limit + recOverhead)) limit recOverhead
  simp only [recordsFill]
  split <;> split <;> dsimp only <;> omega

/-- `records_fill`'s answer carries at least the whole records' plaintext. -/
private theorem recordsFill_whole_mul_le_fill (cap limit : Nat) :
    (recordsFill cap limit).whole * limit ≤ (recordsFill cap limit).fill := by
  simp only [recordsFill]
  split <;> split <;> dsimp only <;> omega

/-- `records_fill` counts at most `cap` records, since each takes a byte of
`cap` or more. -/
private theorem recordsFill_records_le (cap limit : Nat) :
    (recordsFill cap limit).records ≤ cap := by
  have h_quotient := Nat.div_le_self cap (limit + recOverhead)
  have h_overhead : cap / (limit + recOverhead) + 1 ≤
      (cap / (limit + recOverhead) + 1) * recOverhead :=
    Nat.le_mul_of_pos_right _ (by decide)
  simp only [recordsFill]
  split <;> split <;> dsimp only <;> omega

/-- Every sum and product `records_fill` computes fits a `size_t` of `w` bits:
`limit + REC_OVERHEAD`, `whole * limit`, `whole + 1` and
`(whole + 1) * REC_OVERHEAD`. It needs a `limit` of 1 or more, which
`ch_writable_len` checks before the call: at a `limit` of 0,
`(whole + 1) * REC_OVERHEAD` is `2^w` or more for a `cap` near `2^w`. -/
theorem recordsFill_fits (w cap limit : Nat) (h_width : 15 ≤ w) (h_cap : cap < 2 ^ w)
    (h_limit_pos : 1 ≤ limit) (h_limit : limit ≤ txPtMax) :
    limit + recOverhead < 2 ^ w ∧ (recordsFill cap limit).inWhole < 2 ^ w ∧
      (recordsFill cap limit).whole + 1 < 2 ^ w ∧ (recordsFill cap limit).overhead < 2 ^ w := by
  have h_pow_15 : 2 ^ 15 ≤ 2 ^ w := Nat.pow_le_pow_right (by decide) h_width
  have h_quotient := Nat.div_mul_le_self cap (limit + recOverhead)
  have h_product := Nat.mul_add (cap / (limit + recOverhead)) limit recOverhead
  have h_whole_le_in_whole : cap / (limit + recOverhead) ≤ cap / (limit + recOverhead) * limit :=
    Nat.le_mul_of_pos_right _ h_limit_pos
  simp only [recordsFill]
  split <;> split <;> dsimp only <;> simp only [recOverhead, txPtMax] at * <;> omega

/-- Every product and sum `fill_across_key_update` computes is at most `cap`, so
it fits the `size_t` that holds `cap`: `room * (limit + REC_OVERHEAD)`, which
is `room` whole records; the clamp's `(REC_AES_GCM_RECORDS_MAX - 1) * limit`,
when the clamp runs; and the return value, `room * limit + after`. `room` is
below the records `cap` carries, as `ch_writable_len` checks before the call,
and every one of them but the last is whole, so `room` whole records fit `cap`.
`rest` is at most `cap`, so `recordsFill_fits` covers the `records_fill` call
on it, and `limit + REC_OVERHEAD`. -/
theorem fillAcrossKeyUpdate_fits (cap limit room : Nat)
    (h_room : room < (recordsFill cap limit).records) :
    room * (limit + recOverhead) ≤ cap ∧
      ((fillAcrossKeyUpdate cap limit room).records > aesGcmRecordsMax - 1 →
        (aesGcmRecordsMax - 1) * limit ≤ cap) ∧
      (fillAcrossKeyUpdate cap limit room).fill ≤ cap := by
  have h_room_whole : room ≤ (recordsFill cap limit).whole := by
    rcases recordsFill_records cap limit with h_count | h_count <;> omega
  have h_room_fits : room * (limit + recOverhead) ≤ cap :=
    Nat.le_trans (Nat.mul_le_mul_right _ h_room_whole) (recordsFill_whole_mul_le cap limit)
  -- rest is what cap holds after those records and the KeyUpdate record.
  have h_rest_fits :
      (fillAcrossKeyUpdate cap limit room).rest + room * (limit + recOverhead) ≤ cap := by
    simp only [fillAcrossKeyUpdate]
    split <;> omega
  generalize h_rest : (fillAcrossKeyUpdate cap limit room).rest = rest at h_rest_fits
  simp only [fillAcrossKeyUpdate] at h_rest ⊢
  rw [h_rest]
  -- The clamp runs only when rest holds REC_AES_GCM_RECORDS_MAX - 1 whole records,
  -- whose plaintext is at most rest.
  have h_fill_le := recordsFill_fill_le rest limit
  have h_clamp : (recordsFill rest limit).records > aesGcmRecordsMax - 1 →
      (aesGcmRecordsMax - 1) * limit ≤ rest := by
    intro h_over
    have h_whole_at_least : aesGcmRecordsMax - 1 ≤ (recordsFill rest limit).whole := by
      rcases recordsFill_records rest limit with h_count | h_count <;> omega
    calc (aesGcmRecordsMax - 1) * limit
        ≤ (recordsFill rest limit).whole * limit := Nat.mul_le_mul_right limit h_whole_at_least
      _ ≤ (recordsFill rest limit).fill := recordsFill_whole_mul_le_fill rest limit
      _ ≤ rest := h_fill_le
  have h_product := Nat.mul_add room limit recOverhead
  split <;> omega

/-- `ch_writable_len`'s answer is at most `cap`, for every `limit` and every
`room`, `SIZE_MAX` for a ChaCha20-Poly1305 key among them. -/
theorem writableLen_le_cap (cap limit room : Nat) : writableLen cap limit room ≤ cap := by
  simp only [writableLen]
  split
  · exact Nat.zero_le cap
  · split
    · rename_i h_crosses
      exact (fillAcrossKeyUpdate_fits cap limit room h_crosses).2.2
    · exact recordsFill_fill_le cap limit

/-- At a `room` of `cap` or more, `ch_writable_len` answers what `records_fill`
answers and counts no KeyUpdate. `SIZE_MAX`, the `room` of a ChaCha20-Poly1305
key, is at least every `cap` a `size_t` holds, so this is the answer of a
build without `-DCH_SUITE_AES_GCM`, which has no `room`. -/
theorem writableLen_of_cap_le_room (cap limit room : Nat) (h_limit_pos : 1 ≤ limit)
    (h_room : cap ≤ room) : writableLen cap limit room = (recordsFill cap limit).fill := by
  have h_records := recordsFill_records_le cap limit
  simp only [writableLen]
  rw [if_neg (by omega), if_neg (by omega)]

set_option compiler.extract_closed false in
/-- The rows the C's own tests state, at the two limits they use. At a limit of
512, `tls.h`'s: a record of no byte, of one byte, of 512 bytes, and one byte
more; and 0 at a limit of 0. At a limit of 63, `test/key_limit_cases.h`'s: at
an AES-GCM key's ceiling a record of one byte costs a KeyUpdate record as well;
one record before it, the first record does not and the second does; and at
the largest `cap` one KeyUpdate and no second. `2^64 - 1` is `SIZE_MAX` on a
64-bit host. -/
def selftest (_ : Unit) : Bool :=
  let sizeMax := 2 ^ 64 - 1
  let record := 63 + recOverhead
  let keyUpdateAndByte := keyUpdateRecordLen + recOverhead + 1
  writableLen recOverhead 512 sizeMax == 0 &&
  writableLen (recOverhead + 1) 512 sizeMax == 1 &&
  writableLen (512 + recOverhead) 512 sizeMax == 512 &&
  writableLen (512 + 2 * recOverhead) 512 sizeMax == 512 &&
  writableLen (512 + 2 * recOverhead + 1) 512 sizeMax == 513 &&
  writableLen 4096 0 sizeMax == 0 &&
  writableLen (keyUpdateAndByte - 1) 63 0 == 0 &&
  writableLen keyUpdateAndByte 63 0 == 1 &&
  writableLen sizeMax 63 0 == (aesGcmRecordsMax - 1) * 63 &&
  writableLen (recOverhead + 1) 63 1 == 1 &&
  writableLen record 63 1 == 63 &&
  writableLen (record + keyUpdateAndByte - 1) 63 1 == 63 &&
  writableLen (record + keyUpdateAndByte) 63 1 == 64 &&
  writableLen sizeMax 63 1 == aesGcmRecordsMax * 63

end Spec.TlsWrite
