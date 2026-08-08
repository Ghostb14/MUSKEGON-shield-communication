# MUSKEGON Shield Communication Artifact Persistence Policy

## Purpose

Engineering artifacts must not be treated as durable merely because they exist in `/mnt/data`. `/mnt/data` is an execution workspace and may disappear between runs.

## Durable storage rule

Every engineering run that creates a report, checkpoint, validation record, source patch, manifest, checksum, candidate package, or validated release must attempt to persist the artifact to this GitHub repository before reporting it as durable.

Text artifacts should be committed under `engineering/` or `docs/`. Binary ZIP artifacts should be committed as repository blobs/trees when write tooling supports binary-safe writes, or otherwise clearly reported as temporary until durable upload succeeds.

## Link truthfulness rule

A `sandbox:/mnt/data/...` link may be shown only after the exact path is checked in the current runtime immediately before the response. Such a link must be described as temporary unless the same artifact is also persisted durably.

Never present a historical `/mnt/data` path as downloadable without rechecking that it exists in the current runtime.

## Validated release rule

A release may be recorded as `VALIDATED RELEASE` only when all of the following are true:

1. Product source files were actually changed.
2. Source-tree full deep regression completed with zero failures.
3. Exact clean-extraction full deep regression completed with zero failures.
4. Package SHA-256, immutable manifest, archive safety, startup/migration, and affected security-boundary checks passed.
5. The exact package bytes and validation evidence are durably persisted or the report explicitly says durable publication is still pending.

## Baseline recovery rule

The current expected baseline is v10.19.0 Recovery Artifact Provenance & Stable-Hash Assurance:

- Archive: `muskegon-shield-communication-v10.19.0-recovery-artifact-provenance-assurance-release.zip`
- Expected SHA-256: `136dd28c5758379e214d31e2815f808a14463221021c3c77ad7560ef59af66c9`

This entry records the expected identity only. It does not prove that the bytes are currently present in this repository.

## Failure behavior

A persistence failure must never disable or pause the hourly engineering automation. It is a per-run repair target. The run should attempt same-run recovery, preserve truthful status, and retry on the next scheduled run.
