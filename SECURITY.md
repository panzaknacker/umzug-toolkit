# Security policy

## Support status

Version 0.2.0rc1 is a release candidate with no production support. The
intended hardware scope is defined in [HARDWARE-TEST.md](docs/HARDWARE-TEST.md).

## Reporting a vulnerability

When available, use GitHub's private vulnerability reporting under the
repository's **Security** tab. If that channel is unavailable, open an issue
requesting a private reporting channel, without describing the vulnerability.
Private reviewers may use their existing agreed contact channel.

Do not post signing keys, migration contents, hostnames or personal file paths in public issues.
Include the affected commit and component, the trust boundary involved,
expected behavior and a minimal reproduction with synthetic inputs in the
private report. There is no guaranteed response time or security support SLA.

## Evaluation boundaries

Use disposable systems and synthetic data. A successful scanner result does
not guarantee malware-free content; local tests do not qualify privileged
restore or a hardware migration.
