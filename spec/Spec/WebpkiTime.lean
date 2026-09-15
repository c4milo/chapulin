import Spec.Bytes
import Spec.X509Der

/-!
Dates for the web PKI trust mode, written from RFC 5280 §4.1.2.5 and
the proleptic Gregorian calendar (RFC 3339 §5.7 states the leap-year
rule) — never from the C sources.

A Time is UTCTime `YYMMDDHHMMSSZ`, whose two-digit year §4.1.2.5 reads
as 1950..1999 for 50..99 and 2000..2049 for 00..49, or GeneralizedTime
`YYYYMMDDHHMMSSZ`, which the same section reserves for 2050 on. Each
field is held to its range, the day to its month's length in its year.
The packed form is the decimal number YYYYMMDDHHMMSS, so two dates
compare as one integer compare and a validity check is three of them.
`packSeconds` puts a count of seconds since 1970-01-01T00:00:00Z into
the same form. Line ops: `webpki_time <hex>` → `ok <packed> <end>` /
`ERR webpki_time reject`, where end is the offset past the Time;
`webpki_pack <seconds>` → `<packed>`.
-/

namespace Spec.WebpkiTime

open Spec.Bytes
open Spec.X509 (byteAt? readLen)

/-- The Gregorian rule: a multiple of 4 that is not a multiple of 100,
or a multiple of 400 (RFC 3339 §5.7). -/
def isLeap (y : Nat) : Bool := (y % 4 == 0 && y % 100 != 0) || y % 400 == 0

/-- Days in month `m` (1..12) of a year whose leap status is `leap`. -/
def monthLength (leap : Bool) (m : Nat) : Nat :=
  if m == 2 then (if leap then 29 else 28)
  else if m == 4 || m == 6 || m == 9 || m == 11 then 30
  else 31

/-- The six fields of one instant. -/
structure Fields where
  /-- Four-digit year. -/
  year : Nat
  /-- Month, 1..12. -/
  month : Nat
  /-- Day of the month, 1..the month's length. -/
  day : Nat
  /-- Hour, 0..23. -/
  hour : Nat
  /-- Minute, 0..59. -/
  minute : Nat
  /-- Second, 0..59. -/
  second : Nat
  deriving Repr, DecidableEq

/-- RFC 5280 §4.1.2.5's field ranges, with the day held to its month
in its year. -/
def Fields.valid (f : Fields) : Bool :=
  1 ≤ f.month && f.month ≤ 12 && 1 ≤ f.day && f.day ≤ monthLength (isLeap f.year) f.month &&
    f.hour ≤ 23 && f.minute ≤ 59 && f.second ≤ 59

/-- The packed decimal form YYYYMMDDHHMMSS. -/
def Fields.pack (f : Fields) : Nat :=
  f.year * 10000000000 + f.month * 100000000 + f.day * 1000000 + f.hour * 10000 +
    f.minute * 100 + f.second

/-- One ASCII decimal digit. -/
def digit? (b : UInt8) : Option Nat :=
  if 0x30 ≤ b.toNat && b.toNat ≤ 0x39 then some (b.toNat - 0x30) else none

/-- Two digits at `off`, as a number below 100. -/
def pair? (b : ByteArray) (off : Nat) : Option Nat := do
  let hi ← digit? (← byteAt? b off)
  let lo ← digit? (← byteAt? b (off + 1))
  some (hi * 10 + lo)

/-- A UTCTime year: two digits, read by §4.1.2.5's century rule.
Returns the year and the offset past it. -/
def utcYear? (b : ByteArray) (off : Nat) : Option (Nat × Nat) := do
  let yy ← pair? b off
  some (if 50 ≤ yy then 1900 + yy else 2000 + yy, off + 2)

/-- A GeneralizedTime year: four digits, admitted from 2050 on because
§4.1.2.5 makes UTCTime the only encoding of a date through 2049.
Returns the year and the offset past it. -/
def generalizedYear? (b : ByteArray) (off : Nat) : Option (Nat × Nat) := do
  let hi ← pair? b off
  let lo ← pair? b (off + 2)
  guard (2050 ≤ hi * 100 + lo)
  some (hi * 100 + lo, off + 4)

/-- The year of a Time body at `off`, by the shape its tag named. -/
def year? (utc : Bool) (b : ByteArray) (off : Nat) : Option (Nat × Nat) :=
  if utc then utcYear? b off else generalizedYear? b off

/-- The shape a Time's tag names: UTCTime (0x17) or GeneralizedTime
(0x18); any other tag is refused. -/
def shape? (tag : UInt8) : Option Bool :=
  if tag == 0x17 then some true else if tag == 0x18 then some false else none

/-- The five two-digit fields after the year, then the 'Z' that is
the only admitted zone. -/
def clock? (year : Nat) (b : ByteArray) (off : Nat) : Option Fields := do
  let month ← pair? b off
  let day ← pair? b (off + 2)
  let hour ← pair? b (off + 4)
  let minute ← pair? b (off + 6)
  let second ← pair? b (off + 8)
  let zone ← byteAt? b (off + 10)
  guard (zone == 0x5a)
  some ⟨year, month, day, hour, minute, second⟩

/-- One Time TLV at `off`: its packed value and the offset past it.
The tag picks the shape, the length must be that shape's (13 or 15)
in X.690 §10.1's minimal form, and every field must be in range. -/
def readTime (b : ByteArray) (off : Nat) : Option (Nat × Nat) := do
  let tag ← byteAt? b off
  let utc ← shape? tag
  let (len, bodyOff) ← readLen b (off + 1)
  guard (len == if utc then 13 else 15)
  let (year, clockOff) ← year? utc b bodyOff
  let f ← clock? year b clockOff
  guard f.valid
  some (f.pack, bodyOff + len)

/-! ## The caller's clock -/

/-- The last second of the year 9999, 9999-12-31T23:59:59Z. A later
clock packs as this instant: RFC 5280 §4.1.2.5 gives 99991231235959Z
to a certificate with no well-defined expiration, and no Time packs
higher, so the packed clock never leaves the range `readTime` has. -/
def secondsMax : Nat := 253402300799

/-- Days in a year. -/
def yearLength (y : Nat) : Nat := if isLeap y then 366 else 365

/-- Subtracts whole years from the day count `d`, starting with the
length of year `y`, at most `fuel` times. Returns the year it stopped
at and the days left. -/
def subtractYears : Nat → Nat → Nat → Nat × Nat
  | 0, y, d => (y, d)
  | fuel + 1, y, d =>
    if d < yearLength y then (y, d) else subtractYears fuel (y + 1) (d - yearLength y)

/-- Subtracts whole months from the day of the year `d`, starting with
the length of month `m`, at most `fuel` times. Returns the month it
stopped at and the one-based day inside it. -/
def subtractMonths : Nat → Bool → Nat → Nat → Nat × Nat
  | 0, _, m, d => (m, d + 1)
  | fuel + 1, leap, m, d =>
    if d < monthLength leap m then (m, d + 1)
    else subtractMonths fuel leap (m + 1) (d - monthLength leap m)

/-- The years `subtractYears` may subtract from 1970: any count past
the 8030 years through 9999 serves, and 8040 keeps `365 * yearFuel`
above the largest day count `secondsMax` yields (2932896), which the
range lemmas use. -/
def yearFuel : Nat := 8040

/-- The month and day of a day of the year, packed as MMDD. -/
def monthDay (leap : Bool) (doy : Nat) : Nat :=
  let md := subtractMonths 11 leap 1 doy
  md.1 * 100 + md.2

/-- The date `days` after 1970-01-01, packed as YYYYMMDD. -/
def dateOfDays (days : Nat) : Nat :=
  let yd := subtractYears yearFuel 1970 days
  yd.1 * 10000 + monthDay (isLeap yd.1) yd.2

/-- Seconds into a day, packed as HHMMSS. -/
def timeOfDay (t : Nat) : Nat := t / 3600 * 10000 + t % 3600 / 60 * 100 + t % 60

/-- Seconds since 1970-01-01T00:00:00Z in the packed form, clamped at
`secondsMax`. -/
def packSeconds (s : Nat) : Nat :=
  let s := min s secondsMax
  dateOfDays (s / 86400) * 1000000 + timeOfDay (s % 86400)

/-- Structural checks: the century split, the GeneralizedTime floor,
the leap rule at 2024, 2023 and 2100, and the clock at 1970-01-01,
2000-02-29 and 2100-01-01. -/
def selftest : Bool :=
  let utc (body : String) : Option (Nat × Nat) :=
    readTime (ByteArray.mk #[0x17, 13] ++ ascii body) 0
  let gen (body : String) : Option (Nat × Nat) :=
    readTime (ByteArray.mk #[0x18, 15] ++ ascii body) 0
  utc "490101000000Z" == some (20490101000000, 15)
    && utc "500101000000Z" == some (19500101000000, 15)
    && gen "20490101000000Z" == none
    && gen "20500101000000Z" == some (20500101000000, 17)
    && utc "240229000000Z" == some (20240229000000, 15)
    && utc "230229000000Z" == none
    && gen "21000229000000Z" == none
    && gen "20500101240000Z" == none
    && gen "20500101000000+" == none
    && packSeconds 0 == 19700101000000
    && packSeconds 951782400 == 20000229000000
    && packSeconds 4102444800 == 21000101000000
    && packSeconds secondsMax == 99991231235959
    && packSeconds (secondsMax + 1) == 99991231235959

/-!
## Proofs

The mode's validity check depends on two facts. The packed clock keeps
the order of clocks, so `notBefore <= now <= notAfter` on packed numbers
gives the same answer as on the instants they pack; and every value
`readTime` accepts lies in the packed range of a real date, so the
clock — clamped to the same range — is compared against nothing outside
it.
-/

private theorem of_guard_eq_some {p : Prop} [Decidable p] {u : Unit}
    (h : (guard p : Option Unit) = some u) : p := by
  unfold guard at h
  split at h
  · assumption
  · simp at h

/-! ### The clock keeps its order -/

private theorem timeOfDay_lt (t : Nat) (h_in_day : t < 86400) : timeOfDay t < 1000000 := by
  unfold timeOfDay
  omega

private theorem timeOfDay_mono (t t' : Nat) (h_le : t ≤ t') : timeOfDay t ≤ timeOfDay t' := by
  unfold timeOfDay
  omega

private theorem yearLength_ge (y : Nat) : 365 ≤ yearLength y := by
  unfold yearLength
  split <;> omega

private theorem yearLength_le (y : Nat) : yearLength y ≤ 366 := by
  unfold yearLength
  split <;> omega

/-- Subtracting years never lowers the year. -/
private theorem subtractYears_year_ge : ∀ (fuel y d : Nat), y ≤ (subtractYears fuel y d).1 := by
  intro fuel
  induction fuel with
  | zero => intro y d; simp [subtractYears]
  | succ n ih =>
    intro y d
    simp only [subtractYears]
    split
    · exact Nat.le_refl y
    · have h_next := ih (y + 1) (d - yearLength y)
      omega

/-- With fuel for every whole year the count holds, the days left are
fewer than the length of the year returned. -/
private theorem subtractYears_doy_lt : ∀ (fuel y d : Nat), d < 365 * fuel →
    (subtractYears fuel y d).2 < yearLength (subtractYears fuel y d).1 := by
  intro fuel
  induction fuel with
  | zero => intro y d h_fuel; omega
  | succ n ih =>
    intro y d h_fuel
    simp only [subtractYears]
    split
    · next h_inside => simpa using h_inside
    · next h_past =>
      have h_year := yearLength_ge y
      exact ih (y + 1) (d - yearLength y) (by omega)

/-- A later day count returns a later year, or the same year and a
later day inside it. -/
private theorem subtractYears_lex : ∀ (fuel y d d' : Nat), d < d' →
    (subtractYears fuel y d).1 < (subtractYears fuel y d').1 ∨
      ((subtractYears fuel y d).1 = (subtractYears fuel y d').1 ∧
        (subtractYears fuel y d).2 < (subtractYears fuel y d').2) := by
  intro fuel
  induction fuel with
  | zero => intro y d d' h_lt; right; simpa [subtractYears] using h_lt
  | succ n ih =>
    intro y d d' h_lt
    simp only [subtractYears]
    by_cases h_later_inside : d' < yearLength y
    · rw [if_pos h_later_inside, if_pos (by omega)]
      right
      exact ⟨rfl, h_lt⟩
    · rw [if_neg h_later_inside]
      by_cases h_inside : d < yearLength y
      · rw [if_pos h_inside]
        left
        have h_next := subtractYears_year_ge n (y + 1) (d' - yearLength y)
        simp only
        omega
      · rw [if_neg h_inside]
        exact ih (y + 1) (d - yearLength y) (d' - yearLength y) (by omega)

/-- Inside one year, the next day of the year packs strictly higher:
checked by evaluation over every day of a leap and a common year. -/
private theorem monthDay_succ (leap : Bool) (d : Nat) (h_in_year : d < 365) :
    monthDay leap d < monthDay leap (d + 1) := by
  have h_all : (List.range 365).all
      (fun d => decide (monthDay leap d < monthDay leap (d + 1))) = true := by
    cases leap <;> decide +kernel
  rw [List.all_eq_true] at h_all
  simpa using h_all d (List.mem_range.mpr h_in_year)

/-- Every day of the year packs between 0101 and 1231 (or 1232, the
day after a common year's last day, which `subtractMonths` returns
once its fuel is spent, and which `subtractYears_doy_lt` shows
`dateOfDays` never passes). -/
private theorem monthDay_bounds (leap : Bool) (d : Nat) (h_in_year : d < 366) :
    101 ≤ monthDay leap d ∧ monthDay leap d < 10000 := by
  have h_all : (List.range 366).all
      (fun d => decide (101 ≤ monthDay leap d ∧ monthDay leap d < 10000)) = true := by
    cases leap <;> decide +kernel
  rw [List.all_eq_true] at h_all
  simpa using h_all d (List.mem_range.mpr h_in_year)

private theorem monthDay_lt_of_lt (leap : Bool) (d d' : Nat) (h_lt : d < d')
    (h_in_year : d' < 366) : monthDay leap d < monthDay leap d' := by
  induction d' with
  | zero => omega
  | succ k ih =>
    rcases Nat.lt_or_ge d k with h_before | h_at
    · exact Nat.lt_trans (ih h_before (by omega)) (monthDay_succ leap k (by omega))
    · have h_eq : d = k := by omega
      subst h_eq
      exact monthDay_succ leap d (by omega)

/-- A later day count packs a strictly later date, as long as the
fuel covers it. -/
private theorem dateOfDays_lt (days days' : Nat) (h_lt : days < days')
    (h_fuel : days' < 365 * yearFuel) : dateOfDays days < dateOfDays days' := by
  unfold dateOfDays
  dsimp only
  have h_lex := subtractYears_lex yearFuel 1970 days days' h_lt
  have h_doy := subtractYears_doy_lt yearFuel 1970 days (by omega)
  have h_doy' := subtractYears_doy_lt yearFuel 1970 days' h_fuel
  have h_year_le := yearLength_le (subtractYears yearFuel 1970 days).1
  have h_year_le' := yearLength_le (subtractYears yearFuel 1970 days').1
  have h_md := monthDay_bounds (isLeap (subtractYears yearFuel 1970 days).1)
    (subtractYears yearFuel 1970 days).2 (by omega)
  have h_md' := monthDay_bounds (isLeap (subtractYears yearFuel 1970 days').1)
    (subtractYears yearFuel 1970 days').2 (by omega)
  rcases h_lex with h_year_lt | ⟨h_year_eq, h_doy_lt⟩
  · omega
  · have h_inside := monthDay_lt_of_lt (isLeap (subtractYears yearFuel 1970 days).1)
      (subtractYears yearFuel 1970 days).2 (subtractYears yearFuel 1970 days').2 h_doy_lt (by omega)
    rw [h_year_eq] at h_inside ⊢
    omega

/-- The packed clock keeps the order of clocks: for any two counts of
seconds, the earlier packs no higher than the later. This is what
lets `notBefore <= now <= notAfter` compare packed numbers. -/
theorem packSeconds_mono (a b : Nat) (h_le : a ≤ b) : packSeconds a ≤ packSeconds b := by
  unfold packSeconds
  dsimp only
  have h_min : min a secondsMax ≤ min b secondsMax := by omega
  have h_cap : min b secondsMax ≤ secondsMax := Nat.min_le_right _ _
  generalize min a secondsMax = x at h_min ⊢
  generalize min b secondsMax = y at h_min h_cap ⊢
  have h_fuel : y / 86400 < 365 * yearFuel := by
    unfold secondsMax at h_cap
    unfold yearFuel
    omega
  rcases Nat.lt_or_ge (x / 86400) (y / 86400) with h_day_lt | h_day_ge
  · have h_date := dateOfDays_lt _ _ h_day_lt h_fuel
    have h_time := timeOfDay_lt (x % 86400) (Nat.mod_lt _ (by decide))
    omega
  · have h_day_eq : x / 86400 = y / 86400 := by omega
    have h_rem : x % 86400 ≤ y % 86400 := by omega
    have h_time := timeOfDay_mono _ _ h_rem
    rw [h_day_eq]
    omega

/-! ### An accepted Time packs inside the range -/

private theorem digit?_lt (c : UInt8) (v : Nat) (h : digit? c = some v) : v < 10 := by
  unfold digit? at h
  split at h
  · next h_digit =>
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h_digit
    simp only [Option.some.injEq] at h
    omega
  · simp at h

private theorem pair?_lt (b : ByteArray) (off v : Nat) (h : pair? b off = some v) : v < 100 := by
  unfold pair? at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨_, _, hi, h_hi, _, _, lo, h_lo, h_some⟩ := h
  simp only [Option.some.injEq] at h_some
  have h_hi_lt := digit?_lt _ _ h_hi
  have h_lo_lt := digit?_lt _ _ h_lo
  omega

/-- RFC 5280 §4.1.2.5's two rules give one range: UTCTime yields
1950..2049 and GeneralizedTime 2050..9999. -/
private theorem utcYear?_range (b : ByteArray) (off y off' : Nat)
    (h : utcYear? b off = some (y, off')) : 1950 ≤ y ∧ y ≤ 2049 := by
  unfold utcYear? at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨yy, h_yy, h_some⟩ := h
  simp only [Option.some.injEq, Prod.mk.injEq] at h_some
  have h_lt := pair?_lt _ _ _ h_yy
  split at h_some <;> omega

private theorem generalizedYear?_range (b : ByteArray) (off y off' : Nat)
    (h : generalizedYear? b off = some (y, off')) : 2050 ≤ y ∧ y ≤ 9999 := by
  unfold generalizedYear? at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨hi, h_hi, lo, h_lo, _, h_guard, h_some⟩ := h
  simp only [Option.some.injEq, Prod.mk.injEq] at h_some
  have h_floor := of_guard_eq_some h_guard
  have h_hi_lt := pair?_lt _ _ _ h_hi
  have h_lo_lt := pair?_lt _ _ _ h_lo
  omega

/-- RFC 5280 §4.1.2.5's two rules give one range: UTCTime yields
1950..2049 and GeneralizedTime 2050..9999. -/
private theorem year?_range (utc : Bool) (b : ByteArray) (off y off' : Nat)
    (h : year? utc b off = some (y, off')) : 1950 ≤ y ∧ y ≤ 9999 := by
  unfold year? at h
  cases utc with
  | true =>
    have h_utc := utcYear?_range _ _ _ _ (by simpa using h)
    omega
  | false =>
    have h_generalized := generalizedYear?_range _ _ _ _ (by simpa using h)
    omega

private theorem clock?_year (year : Nat) (b : ByteArray) (off : Nat) (f : Fields)
    (h : clock? year b off = some f) : f.year = year := by
  unfold clock? at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, h_some⟩ := h
  simp only [Option.some.injEq] at h_some
  rw [← h_some]

private theorem monthLength_le (leap : Bool) (m : Nat) : monthLength leap m ≤ 31 := by
  unfold monthLength
  split
  · split <;> omega
  · split <;> omega

/-- Valid fields with a four-digit year from 1950 pack between the
first instant of 1950 and the last of 9999. -/
private theorem Fields.pack_range (f : Fields) (h_valid : f.valid = true)
    (h_year_ge : 1950 ≤ f.year) (h_year_le : f.year ≤ 9999) :
    19500101000000 ≤ f.pack ∧ f.pack ≤ 99991231235959 := by
  unfold Fields.valid at h_valid
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h_valid
  have h_month := monthLength_le (isLeap f.year) f.month
  unfold Fields.pack
  omega

/-- Every value `readTime` accepts is the packed form of a date between
1950-01-01T00:00:00Z and 9999-12-31T23:59:59Z, the range the clamped
clock also stays in, so validity never compares against a number no
instant has. -/
theorem readTime_range (b : ByteArray) (off p off' : Nat)
    (h : readTime b off = some (p, off')) : 19500101000000 ≤ p ∧ p ≤ 99991231235959 := by
  unfold readTime at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨_, _, utc, _, ⟨_, _⟩, _, _, _, ⟨year, _⟩, h_year, f, h_clock, _, h_guard, h_some⟩ := h
  simp only [Option.some.injEq, Prod.mk.injEq] at h_some
  have h_range := year?_range _ _ _ _ _ h_year
  have h_field_year := clock?_year _ _ _ _ h_clock
  have h_valid := of_guard_eq_some h_guard
  rw [← h_some.1]
  exact Fields.pack_range f h_valid (by omega) (by omega)

end Spec.WebpkiTime
