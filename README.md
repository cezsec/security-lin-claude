# Linux security scripts

Three standalone Bash tools. Each is a single file you can copy to a server and run.

| Tool | Use it to | Changes the system? |
|---|---|---|
| `harden.sh` | Audit an Ubuntu 22.04+ server against a CIS-style baseline and, with `--harden`, fix what it finds | Only with `--harden` (backed up; `--rollback` reverts) |
| `secmon.sh` | Audit the host and analyse the last N hours of logs for brute force, spraying, logins after failures, privilege escalation, and more; can run from cron or `--watch` | No |
| `linux_persistence_hunter.sh` | Triage a host you suspect is compromised, or a mounted disk image (`--root`), for persistence and rootkit indicators | Never |

## Quick start

```bash
sudo ./harden.sh                      # audit only
sudo ./harden.sh --harden --dry-run   # preview fixes
sudo ./secmon.sh --hours 24           # audit + last 24h of logs
sudo ./linux_persistence_hunter.sh    # compromise triage, reports in ./persistence-report-*
sudo ./linux_persistence_hunter.sh -r /mnt/evidence   # offline image
```

All three write HTML plus machine-readable reports (JSON or CSV) and use exit codes you can script against. Run each with `--help` for every option.

## Run time

- The slowest step is checking package files against their checksums (`dpkg --verify`). This runs in the hunter by default and in `secmon.sh --deep`. It uses up to 4 parallel jobs and takes about 15 s on a desktop-sized install. Skip it with `linux_persistence_hunter.sh -q`.
- `secmon.sh --quick` skips the file system scan, the traffic sample and DNS lookups.

## A clean package check is not proof

Package checksums come from the host's own package database. An attacker with root can rewrite that database. For certainty, compare against packages from a trusted mirror or boot from rescue media.

## Tests

```bash
bash tests/smoke.sh
```

The tests run without root and write only to a temporary directory:
- the hunter against a small fake image with planted persistence
- secmon against a synthetic brute-force `auth.log`
- the harden audit functions

CI (`.github/workflows/ci.yml`) runs shellcheck and these tests.
