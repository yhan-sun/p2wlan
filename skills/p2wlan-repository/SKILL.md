---
name: p2wlan-repository
description: Apply P2WLAN repository contracts when changing documentation, privacy boundaries, deployment tools, release workflows, recovery behavior, or AI maintenance rules.
---

# P2WLAN repository workflow

Use this skill for repository maintenance that can change public documentation or the path from source to a deployed release.

Before editing, read:

- AGENTS.md
- docs/README.md
- every tracked Markdown file under docs/
- the implementation, tests, scripts, and workflow that own the requested behavior

Keep the result in final state. Public docs describe current behavior only; development history and release evidence belong in PRs, Issues, or release assets. Never add personal infrastructure values, secrets, local paths, copied logs, or screenshots with identifiers. Every documented command must resolve to a real tracked entry point or a released package member.

When changing deployment or release behavior, bind the source commit, package checksum, embedded version, and verification target together. Prefer one tested deployment path over several unverified variants. Backup and restore changes must preserve service state, use a consistent database snapshot, validate the restored database, and never silently continue after a failed stop or verification.

Before handoff, run the repository documentation checker and shell syntax checks from AGENTS.md, then run focused tests. Report actual results and any real-device, public-network, or independent-audit work that remains.
