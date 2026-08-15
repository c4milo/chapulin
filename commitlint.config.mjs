// Conventional commits, enforced by .githooks/commit-msg locally and
// `make lint-commits` in check. Bodies keep the house rule: explain WHY,
// wrap at 100 columns.
export default {
    extends: ["@commitlint/config-conventional"],
    rules: {
        "header-max-length": [2, "always", 100],
        "body-max-line-length": [2, "always", 100],
    },
};
