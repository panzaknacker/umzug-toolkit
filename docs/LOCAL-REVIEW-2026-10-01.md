# Local review — 2026-10-01

The [component demo](evidence/2026-10-01-demo.txt) passed all nine cases.
The [real transport smoke test](evidence/2026-10-01-transport.txt) passed
signature and manifest verification, exact extracted bytes, preservation of
an existing target and tamper rejection.

A new full metadata-restore, scanner or hardware qualification was not run.
The [SELinux compatibility limitation](KNOWN-ISSUES.md) remains open.

## Environment and source

Fedora 44 x86_64, kernel 7.2.5-200.fc44; Go 1.26.8 where used and Python
3.14.7. Prepared tools and module caches were reused; Go proxy and checksum
lookups were disabled. Data and keys were synthetic and temporary.

[Context](evidence/2026-10-01-context.json) ·
[Code and build inputs](evidence/2026-10-01-inputs.sha256)

Local checkout and tool paths in the logs were normalized; results were not
changed. Repository history was scanned with Gitleaks 8.30.1 across all refs
without reported findings. This does not audit development history absent
from the snapshot or qualify a production deployment.

[Hosted CI start failures](HOSTED-CI.md) are separate from these local results.
