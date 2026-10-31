# Security Policy

RepoLens is a static analyzer built to inspect untrusted repositories safely. Its threat model,
enforcement points, and known limits are documented in
[docs/security/README.md](docs/security/README.md).

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a vulnerability in RepoLens itself. Report it
privately to the repository owner through GitHub — **Security** tab → *Report a vulnerability*,
when private reporting is available there — with a description, reproduction steps, impact, and a
suggested fix if you have one. Keeping details private until a fix is available is appreciated.
No response-time commitment is made.

Maintainer note: private vulnerability reporting must be enabled by the owner
(Settings → Security → Private vulnerability reporting) for the button above to appear; it was
not enabled when this file was added.

## Supported versions

RepoLens is pre-release (`0.1.1.dev0` in development, no tagged releases). Security fixes land on
`main`; there are no maintained release branches yet.
