-- Run by make lint-spec, never part of the library build: prints the
-- axioms each theorem depends on, and the gate asserts nothing appears
-- beyond Lean's three standard ones (propext, Classical.choice,
-- Quot.sound). A stray axiom in a proof is exactly what this catches;
-- the hygiene grep catches the declaration itself.
--
-- The theorems come from the environment, not from a list in this file. A
-- hand-written list of `#print axioms` lines fell behind the proofs it
-- gated, and nothing reported the omissions: a theorem the list leaves out
-- is a theorem nobody checks. Reading the environment cannot fall behind,
-- because the import that compiles a theorem also puts it in the
-- environment, and it reaches the private theorems, whose stored names a
-- list of source-level names cannot spell. See
-- https://github.com/c4milo/chapulin/issues/42.
import Spec
import Lean

open Lean Elab Command

namespace AxiomCheck

/-- True when `name` is the `Spec` module or one of its submodules. -/
def isSpecModule (name : Name) : Bool :=
  (`Spec).isPrefixOf name

/--
Every theorem the `Spec` modules declare, sorted so two runs print the same
lines in the same order.

Each theorem is selected by the module that declares it, not by the
namespace its name sits in. The two differ, and the difference is large: a
private theorem is stored under a name like
`_private.Spec.Sha3.0.Spec.Sha3.round_size`, which no filter on the `Spec`
namespace matches, and `X509Der.lean` declares into `Spec.X509` rather than
into a namespace of its own. Compiler-generated theorems, such as the
`injEq` of a structure, come from the same modules and get checked too.
-/
def specTheorems (env : Environment) : Array Name :=
  let fromSpec := env.header.moduleNames.map isSpecModule
  let names := env.constants.fold (init := #[]) fun acc name info =>
    if info.isTheorem then
      match env.getModuleIdxFor? name with
      | some idx => if fromSpec.getD idx.toNat false then acc.push name else acc
      | none => acc
    else acc
  names.qsort Name.lt

/--
The module name each `Spec/*.lean` file defines. make lint-spec runs this
file with `spec/` as the working directory, so the path is relative to it.
-/
def specModuleFiles : IO (Array Name) := do
  let mut modules : Array Name := #[]
  for entry in (← System.FilePath.readDir "Spec") do
    if (← entry.path.isDir) then
      throw <| IO.userError s!"Spec/{entry.fileName} is a directory, and this \
        check reads only the flat Spec/*.lean files"
    if entry.fileName.endsWith ".lean" then
      let some stem := entry.path.fileStem
        | throw <| IO.userError s!"Spec/{entry.fileName} has no stem to name a \
            module after"
      modules := modules.push (.str `Spec stem)
  return modules

end AxiomCheck

run_cmd do
  let env ← getEnv
  -- spec/Spec.lean lists its imports by hand, so a new module can miss it.
  -- That module still compiles under lake build, but its theorems never
  -- enter this environment, which is the same gap the hand-written list of
  -- theorems had.
  for module in (← AxiomCheck.specModuleFiles) do
    unless env.header.moduleNames.contains module do
      throwError "{module} exists but spec/Spec.lean does not import it, so \
        its theorems go unchecked"
  let theorems := AxiomCheck.specTheorems env
  -- An empty run would print no axiom lines at all, and the Makefile gate
  -- reads no lines as nothing to report. Fail instead of passing silently.
  if theorems.isEmpty then
    throwError "the Spec modules declare no theorems, so this check would \
      pass without checking anything"
  for name in theorems do
    let axioms ← collectAxioms name
    let listed := ", ".intercalate (axioms.qsort Name.lt |>.toList.map toString)
    -- The shape `#print axioms` emits, which the Makefile gate greps for. A
    -- theorem that rests on no axiom prints an empty list, and the gate
    -- reads that as nothing to report.
    logInfo s!"'{name}' depends on axioms: [{listed}]"
  logInfo s!"AxiomCheck: {theorems.size} theorems checked"
