# Security Policy

RepoLens is a static analyzer built to inspect untrusted repositories safely. Its threat model,
enforcement points, and known limits are documented in
[docs/security/README.md](docs/security/README.md).

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a vulnerability in RepoLens itself. Use the
repository's **Security** → *Report a vulnerability* form to report it privately, including a
description, reproduction steps, impact, and a suggested fix if you have one. Keeping details
private until a fix is available is appreciated. No response-time commitment is made.

GitHub private vulnerability reporting was verified enabled during release-infrastructure review.
The owner should keep it enabled or document another authorized private reporting channel.

## Supported versions

RepoLens is pre-release (`0.1.1.dev1` in development, no tagged releases). Security fixes land on
`main`; there are no maintained release branches yet.
