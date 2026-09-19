#!/usr/bin/env python3
"""Read C source the way tools/quic-footprint.py needs it read.

One concern: what a file says, not what the report makes of it. The
functions here answer seven questions about one .c or .h file -- what
its comments say, what functions it declares, what types it declares,
what function-like macros it defines, what it defines, which standards
it cites, and which of its lines one macro controls -- and resolve()
answers the eighth across the whole mode.

Nothing here knows about QUIC. tools/quic-footprint.py holds the file
list, the counts and the printing, and docs/quic.md states the mode.

The parsing is text, not a compiler, and that bounds what it can see. It
reads a declaration or a definition that a `#if` arm would drop, because
it blanks preprocessor lines rather than evaluating them, and it counts a
function declared twice under two arms once. Both readings suit a report
that answers "how much of this mode exists".
"""

import re

# A declaration's name is the first identifier that opens a paren. These
# are the words that are never that name.
KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "typedef",
    "struct", "union", "enum", "static", "extern", "const", "void",
    "int", "char", "long", "short", "unsigned", "signed", "float",
    "double", "_Static_assert", "_Alignas", "__attribute__",
}

DECLARATOR = re.compile(r"(\w+)\s*\(")

# One pass over a comment reads three things: a standard named in prose,
# an RFC named by a line anchor, and a section mark. The first two say
# which document the marks after them belong to. The headers cite RFCs,
# FIPS publications and NIST special publications, so all three are
# named here; a mode that cited others would need them added, and the
# report's last line says how many marks found no name at all.
CITATION = re.compile(r"(?P<named>RFC\s+[0-9]{3,5}"
                      r"|FIPS\s+[0-9]{3}"
                      r"|SP\s+800-[0-9]+[A-Za-z]*)"
                      r"|rfc(?P<anchor>[0-9]{3,5})\.txt"
                      r"|§\s*(?P<mark>[0-9]+(?:\.[0-9]+)*)")


def strip_comments(text):
    """Return the source with every comment blanked, keeping each byte's
    offset, and the comment text on its own. String literals are blanked
    in the source too, so a brace or paren inside one counts for
    nothing."""
    code, comment = list(text), []
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            while i < n and text[i] != "\n":
                comment.append(text[i])
                code[i] = " "
                i += 1
            comment.append("\n")
        elif two == "/*":
            while i < n and text[i:i + 2] != "*/":
                comment.append(text[i])
                code[i] = " " if text[i] != "\n" else "\n"
                i += 1
            for j in range(i, min(i + 2, n)):
                code[j] = " "
            comment.append("\n")
            i += 2
        elif text[i] in "\"'":
            quote = text[i]
            code[i] = " "
            i += 1
            while i < n and text[i] != quote:
                escaped = text[i] == "\\"
                code[i] = " " if text[i] != "\n" else "\n"
                i += 1
                if escaped and i < n:
                    code[i] = " " if text[i] != "\n" else "\n"
                    i += 1
            if i < n:
                code[i] = " "
            i += 1
        else:
            i += 1
    # Drop the `//` and `*` that open each comment line. A citation wraps
    # (`RFC` at the end of one line, `9000 SS17.2` at the start of the
    # next), and the markers between them would break the name in two.
    text = re.sub(r"(?m)^[ \t]*(?://+|\*/?)[ \t]?", "", "".join(comment))
    return "".join(code), text


def without_directives(code):
    """Blank every preprocessor line, continuations included. A macro
    that takes arguments otherwise reads as a declaration.

    A blanked line keeps its length, so every byte of the result sits at
    the offset it sits at in the file. strip_comments keeps offsets too,
    so stubbed() below can read a body's comments out of the original
    text at the offsets it found the body at."""
    out, keep = [], True
    for line in code.split("\n"):
        stripped = line.strip()
        if keep and stripped.startswith("#"):
            keep = False
        out.append(" " * len(line) if not keep else line)
        if not keep and not stripped.endswith("\\"):
            keep = True
    return "\n".join(out)


def name_of(statement):
    """The declared function's name, or None when the statement declares
    no function. The name is the first identifier that opens a paren:
    `int ch_quic_init(ch_quic *q, const ch_cfg *cfg)` gives
    `ch_quic_init`, and a parameter that is itself a call gives nothing
    before it."""
    match = DECLARATOR.search(statement)
    if match is None or match.group(1) in KEYWORDS:
        return None
    if statement.lstrip().startswith("typedef"):
        return None
    return match.group(1)


def declared(path):
    """Every function name one header declares, in the order written and
    each name once. A header that declares the same function in two `#if`
    arms declares one function, and both arms are read here, so the
    second name is dropped rather than counted again."""
    code, _ = strip_comments(path.read_text())
    code = without_directives(code)
    names, depth, start = [], 0, 0
    for i, char in enumerate(code):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                # A struct or enum body ends here. What follows it is the
                # next statement, and an array bound inside it is gone.
                start = i + 1
        elif char == ";" and depth == 0:
            name = name_of(code[start:i])
            if name is not None and name not in names:
                names.append(name)
            start = i + 1
    return names


# A function-like macro: a #define whose name opens a paren. An
# object-like macro cannot stand in for a call, so it is not one of
# these.
FUNCTION_MACRO = re.compile(r"(?m)^[ \t]*#[ \t]*define[ \t]+(\w+)\(")

# The name inside the parentheses of a function-pointer typedef, and an
# array bound, which typedef_name drops before it reads the last word.
POINTER_NAME = re.compile(r"\(\s*\*\s*(\w+)\s*\)")
ARRAY_BOUND = re.compile(r"\[[^\]]*\]")


def function_macros(path):
    """Every function-like macro one file defines, each name once. The
    comments are blanked first, so a #define written inside one counts
    for nothing."""
    code, _ = strip_comments(path.read_text())
    names = []
    for name in FUNCTION_MACRO.findall(code):
        if name not in names:
            names.append(name)
    return names


def typedef_name(statement):
    """The type name one statement declares, or None when the statement
    is not a typedef. A function-pointer typedef writes its name inside
    parentheses; every other form writes it last, so the last word of
    the statement is the name once any array bound is gone."""
    if not statement.lstrip().startswith("typedef"):
        return None
    found = POINTER_NAME.search(statement)
    if found is not None:
        return found.group(1)
    words = re.findall(r"\w+", ARRAY_BOUND.sub(" ", statement))
    return words[-1] if words else None


# The opening brace of a struct or union body, with the tag before it
# when the definition carries one. A header that writes one of these
# completes a type, and a file that includes that header can then
# declare one, size one and write a field of one.
STRUCT_BODY = re.compile(r"\b(?:struct|union)\s+(\w+)\s*\{")


def complete_types(path):
    """Every type one file defines a body for, in the order written.

    quic_aes.h declares `typedef struct aes_public_key aes_public_key;`
    and stops, so this reads no name there; quic_aes_key.h writes
    `struct aes_public_key { ... };`, so this reads one. INV-26 rests on
    that difference, and tools/quic-footprint.py checks it.

    The same split typedefs() walks: a semicolon at brace depth zero
    ends a statement. A statement holding a brace defines a body, and
    its name is the typedef's name when the statement is a typedef and
    the struct tag otherwise."""
    code, _ = strip_comments(path.read_text())
    code = without_directives(code)
    names, depth, start = [], 0, 0
    for i, char in enumerate(code):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == ";" and depth == 0:
            statement = code[start:i]
            start = i + 1
            if "{" not in statement:
                continue
            name = typedef_name(statement)
            if name is None:
                found = STRUCT_BODY.search(statement)
                name = found.group(1) if found is not None else None
            if name is not None and name not in names:
                names.append(name)
    return names


def typedefs(path):
    """Every type name one header's typedefs declare, in the order
    written and each name once.

    The walk splits on a semicolon at brace depth zero and nowhere
    else, so `typedef struct { ... } aes_public_key;` stays one
    statement. Read a .c file with this and a function body's closing
    brace leaves the next statement joined to the last one, which is
    why headers are what it is written for."""
    code, _ = strip_comments(path.read_text())
    code = without_directives(code)
    names, depth, start = [], 0, 0
    for i, char in enumerate(code):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == ";" and depth == 0:
            name = typedef_name(code[start:i])
            if name is not None and name not in names:
                names.append(name)
            start = i + 1
    return names


def defined(path):
    """Every function name one .c file defines. A definition is a name
    that opens a paren and a body at brace depth zero, which is what
    tools/exact-fill.py walks for the same reason."""
    if not path.exists():
        return None
    code, _ = strip_comments(path.read_text())
    code = without_directives(code)
    names, depth, anchor = [], 0, 0
    for i, char in enumerate(code):
        if char == "{":
            if depth == 0:
                found = DECLARATOR.findall(code[anchor:i])
                kept = [f for f in found if f not in KEYWORDS]
                if kept:
                    names.append(kept[0])
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                anchor = i + 1
        elif char == ";" and depth == 0:
            anchor = i + 1
    return names


# The one form a stub body's marker takes, and the same pattern the
# Makefile's QUIC_STUB_SRCS greps for. A stub is a function that carries
# the header's name and none of its behaviour: it returns the refusal the
# header documents and writes nothing. docs/quic.md, "The stubs and the
# marker", states the rules; the marker is what makes them countable.
STUB_MARKER = re.compile(r"(?m)^[ \t]*// CH_QUIC_STUB: ")


def stubbed(path):
    """Every function one .c file defines whose body carries the stub
    marker, in the order written. None when the file does not exist.

    It walks the same braces defined() walks, and reads each body's
    comments out of the file's own text at the offsets the walk found,
    which strip_comments and without_directives both preserve. A
    function whose body holds no marker is implemented as far as this
    reader can tell, and the test binary is what holds the refusal."""
    if not path.exists():
        return None
    text = path.read_text()
    code = without_directives(strip_comments(text)[0])
    names, depth, anchor, name, start = [], 0, 0, None, 0
    for i, char in enumerate(code):
        if char == "{":
            if depth == 0:
                found = [f for f in DECLARATOR.findall(code[anchor:i]) if f not in KEYWORDS]
                name = found[0] if found else None
                start = i
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                if name is not None and STUB_MARKER.search(text[start:i]):
                    names.append(name)
                anchor = i + 1
        elif char == ";" and depth == 0:
            anchor = i + 1
    return names


def document(match):
    """The standard one citation names, spelled one way. `RFC 9001` and
    `rfc9001.txt` are the same document and answer with the same name,
    and a name that wrapped over a line break loses the break."""
    named = match.group("named")
    if named is not None:
        return re.sub(r"\s+", " ", named)
    anchor = match.group("anchor")
    return None if anchor is None else f"RFC {anchor}"


def subject_doc(comment):
    """The standard a file is mostly about: the one it names most often.
    Ties go to the one it names first, which is the one its opening
    sentence is about."""
    order, count = [], {}
    for match in CITATION.finditer(comment):
        name = document(match)
        if name is None:
            continue
        if name not in count:
            order.append(name)
        count[name] = count.get(name, 0) + 1
    if not order:
        return None
    return max(order, key=lambda doc: (count[doc], -order.index(doc)))


def marks_in(path):
    """Every section mark one file writes, each with the standard whose
    name sits immediately before it, or None when no name does. Also the
    standard the file is mostly about.

    Adjacency is the whole test. `RFC 9001 SS5.4.2` names its own
    standard; `(NIST SP 800-38D) and the SS5.4.3 mask` does not, and
    reading that mark as SP 800-38D's would be wrong -- SS5.4.3 is RFC
    9001's. A rule that let a name carry further than the space next to
    it read several marks into the wrong standard, which is why this one
    stops there and leaves the rest to resolve().
    """
    _, comment = strip_comments(path.read_text())
    found, name, end = [], None, 0
    for match in CITATION.finditer(comment):
        if match.group("named") is not None:
            name, end = document(match), match.end()
        elif match.group("mark") is not None:
            touching = name if not comment[end:match.start()].strip() else None
            found.append((match.group("mark"), touching))
    return found, subject_doc(comment)


def resolve(scan):
    """Give every section mark in the mode a standard, three rules deep.

    A mark with a standard's name against it takes that standard. That
    rule alone leaves the marks that write `SS17.2's cap` a sentence
    after the one that named RFC 9000, so the second rule reads the
    mode's own named citations: a section number that only one standard
    is ever named with belongs to that standard wherever it appears bare.
    A number two standards both name, such as `SS5.2`, stays ambiguous
    and falls to the third rule, the standard its file is mostly about.

    Every rule reads the tree. Nothing here knows how many sections a
    standard has, and a mode that cited a different set would resolve
    against those.
    """
    owner = {}
    for marks, _ in scan.values():
        for section, doc in marks:
            if doc is not None:
                owner.setdefault(section, set()).add(doc)
    out = {"adjacent": [], "section": [], "subject": [], "none": []}
    for path, (marks, subject) in scan.items():
        for section, doc in marks:
            only = owner.get(section, set())
            if doc is not None:
                out["adjacent"].append((doc, section, path))
            elif len(only) == 1:
                out["section"].append((next(iter(only)), section, path))
            elif subject is not None:
                out["subject"].append((subject, section, path))
            else:
                out["none"].append((None, section, path))
    return out


CONDITIONAL = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
IDENTIFIER = re.compile(r"\b([A-Za-z_]\w*)\b")


def conditional_spans(path, macro):
    """Every block of lines one file compiles when `macro` is defined
    and leaves out when it is not, as (opening line, closing line) pairs
    that count from 1.

    Two shapes qualify: the first arm of `#ifdef macro`, and the `#else`
    arm of `#ifndef macro`. A conditional that names another macro
    beside this one does not: a build that defines that other macro
    compiles the arm without `macro`, so the lines are not this macro's
    alone. Nesting is tracked, so an inner conditional inside a counted
    arm does not close it.
    """
    spans, stack = [], []
    for number, line in enumerate(path.read_text().split("\n"), 1):
        found = CONDITIONAL.match(line)
        if found is None:
            continue
        word, rest = found.group(1), found.group(2)
        if word in ("if", "ifdef", "ifndef"):
            names = set(IDENTIFIER.findall(rest)) - {"defined"}
            wanted = None if names != {macro} else (1 if word == "ifndef"
                                                    else 0)
            stack.append({"wanted": wanted, "arm": 0,
                          "open": number if wanted == 0 else None})
            continue
        if not stack:
            continue
        if word == "endif":
            block = stack.pop()
            if block["open"] is not None:
                spans.append((block["open"], number))
            continue
        block = stack[-1]
        if block["open"] is not None:
            spans.append((block["open"], number))
            block["open"] = None
        block["arm"] += 1
        if block["arm"] == block["wanted"]:
            block["open"] = number
    return spans


def section_key(section):
    """Sort sections by each number rather than as text, so `9.5` comes
    before `9.10` the way a table of contents orders them."""
    return tuple(int(part) for part in section.split("."))
