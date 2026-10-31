# Security Policy

RepoLens is a static analyzer built to inspect untrusted repositories safely. Its threat model,
enforcement points, and known limits are documented in
[docs/security/README.md](docs/security/README.md).

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a vulnerability in RepoLens itself. GitHub
private vulnerability reporting is currently disabled, and no alternative private contact is
documented yet. The repository owner must enable it (Settings → Security → Private vulnerability
reporting), or document another authorized private reporting channel, before the first release.

Once GitHub private reporting is enabled, use **Security** → *Report a vulnerability* with a
description, reproduction steps, impact, and a suggested fix if you have one. Keeping details
private until a fix is available is appreciated. No response-time commitment is made.

## Supported versions

RepoLens is pre-release (`0.1.1.dev1` in development, no tagged releases). Security fixes land on
`main`; there are no maintained release branches yet.
