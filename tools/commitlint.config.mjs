// Conventional commits, enforced by .githooks/commit-msg locally and
// `make lint-commits` in check. Bodies keep the house rule: explain WHY,
// wrap at 100 columns.
export default {
    extends: ["@commitlint/config-conventional"],
    rules: {
        "header-max-length": [2, "always", 100],
        "body-max-line-length": [2, "always", 100],
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
    ignores: [(message) => /^Signed-off-by: dependabot\[bot\]/m.test(message)],
};
