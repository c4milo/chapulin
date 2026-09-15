// Conventional commits, enforced by .githooks/commit-msg locally and
// `make lint-commits` in check. Bodies keep the house rule: explain WHY,
// wrap at 100 columns.
// The trailer keys this tree writes, and no others. conventional-commits-parser
// 7 treats every line shaped `word: text` as a git trailer, and its one option,
// issuePrefixes, widens that set and never narrows it, so a body sentence that
// begins `why:` or `recovery:` opens a "footer" in the middle of a paragraph.
// The stock footer-leading-blank rule then warns, and 23 commits already on
// main do exactly that. The set is closed for the same reason: a paragraph
// cannot become a trailer by starting with a capitalised word and a colon.
// Case-insensitive, because three commits on main wrote Co-authored-by. The
// reference keywords take a space as well as a colon, which is how GitHub
// reads them and how this history writes them.
const TRAILER_KEYS = ["Co-Authored-By", "Claude-Session", "Signed-off-by", "Reviewed-by",
    "BREAKING CHANGE"];
const REFERENCE_KEYS = ["Closes", "Fixes", "Refs"];
const trailerLine = new RegExp(
    `^(?:(?:${TRAILER_KEYS.join("|")}): |(?:${REFERENCE_KEYS.join("|")})[: ] ?)\\S`, "i");

// The final run of trailer lines must follow a blank line, so a reader and
// git interpret-trailers agree on where the body ends. A message with no
// trailers passes; a trailer block that is the whole body sits directly
// under the subject's blank line and passes too.
function trailerLeadingBlank(parsed) {
    const lines = parsed.raw.replace(/\s+$/, "").split("\n");
    let start = lines.length;
    while (start > 0 && trailerLine.test(lines[start - 1])) {
        start--;
    }
    if (start === lines.length || start === 0) {
        return [true];
    }
    return [lines[start - 1] === "", "trailers must have a leading blank line"];
}

export default {
    extends: ["@commitlint/config-conventional"],
    plugins: [{ rules: { "trailer-leading-blank": trailerLeadingBlank } }],
    rules: {
        "header-max-length": [2, "always", 100],
        "body-max-line-length": [2, "always", 100],
        // Off: it reads the parser's footer, which starts at any `word: text`
        // line (see TRAILER_KEYS). trailer-leading-blank asks the same
        // question of the real trailers only, and as an error, not a warning.
        "footer-leading-blank": [0],
        "trailer-leading-blank": [2, "always"],
    },
    // Dependabot writes its own body -- release notes, changelog links and a
    // machine-read `updated-dependencies` block -- and wraps none of it, so
    // every one of its commits fails body-max-line-length. Unignored, that
    // turns each Dependabot pull request red and the auto-merge in
    // .github/workflows/dependabot-automerge.yml never fires, because
    // auto-merge waits for the required checks to pass.
    //
    // The test is Dependabot's own sign-off trailer, which a person's commit
    // does not carry. This waives the whole message rather than the body
    // rule alone, because commitlint chooses rules per config and not per
    // commit. What still holds the header to the conventional form is
    // .github/dependabot.yml, which sets the type: `ci` for the Actions
    // updates and `build` for the npm ones.
    ignores: [
        (message) => /^Signed-off-by: dependabot\[bot\]/m.test(message),
        // ad36415 is #132 squash-merged through the GitHub UI, which wrote the
        // pull request's title as the subject with no type. It is on main
        // and cannot be rewritten, and lint-commits-range on main lints the
        // whole history, so without this one exact match every push to main
        // fails check forever. Exactly that header, nothing broader; the
        // pr-title workflow keeps the next squash from landing typeless.
        (message) => message.startsWith("Fail check on a conflict marker in a tracked file (#132)\n"),
    ],
};
