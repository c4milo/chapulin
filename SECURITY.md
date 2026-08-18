# Security policy

## How to report a vulnerability

Use GitHub's private vulnerability reporting: open the repository's
[Security tab](https://github.com/c4milo/chapulin/security) and click
"Report a vulnerability". The report stays private, and the advisory
and CVE, if one is warranted, come out of the same thread.

If you cannot use GitHub, email caguilar@coreweave.com with the same
details you would put in the report.

Do not open a public issue for a vulnerability.

## What to expect

One maintainer runs this project. You get an acknowledgment within
7 days and an assessment — confirmed, not a vulnerability, or needs
more information — within 30. I promise communication, not a fix
date; the fix date comes out of the assessment.

## Scope

In scope: the library as shipped — the TLS client, the crypto
primitives, and the reference DRBG in `drbg.[ch]`.

Out of scope, so triage stays fast:

- Physical side channels: power analysis, electromagnetic leakage,
  fault injection.
- Attacks that require a malicious `ch_cfg`, malicious I/O callbacks,
  or a compromised platform. The caller is trusted; the peer and the
  network are not.
- Denial of service against the device that runs the caller's code.
  The caller owns its own event loop and timeouts.

The [README](README.md)'s verification section and
[docs/decisions.md](docs/decisions.md) state the threat model in
detail: what is proved, at what bounds, and what is only tested.

## Supported versions

The latest release only. One maintainer does not promise backports.

## Disclosure policy

Coordinated disclosure with a 90-day default, negotiable in either
direction — shorter when the fix is easy, longer when a deployment
needs it. Reporters get credited in the advisory unless they decline.
