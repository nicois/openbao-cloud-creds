# openbao-cloud-creds

Short-lived, role-based cloud credentials for [OpenBao](https://openbao.org/), with a uniform API across cloud providers (AWS, GCP, Azure, DigitalOcean, UpCloud, OVH).

**Status:** Design phase. No code yet. See [`docs/techrfc.md`](docs/techrfc.md) for the spec under review.

## What this is

Some clouds support short-lived role-scoped credentials natively (AWS STS, GCP impersonation, Azure dynamic SP). Others issue long-lived API tokens with no native rotation primitive (DigitalOcean, UpCloud, OVH). This project is a set of OpenBao plugins that present a single uniform `bao read cloud-creds/<cloud>/creds/<role>` API regardless, hiding the per-cloud divergence behind one of two strategies:

- **JIT** — for clouds with usable per-request token APIs: mint on read, revoke on lease end. (DigitalOcean is the reference implementation.)
- **Phased rotation** — for clouds without JIT: N pre-provisioned credential slots rotated on schedule with phase offsets, so the freshest slot's TTL is always honest.

Every issued lease's `expires_at` reflects actual remaining validity. Steady-state rotation is fully headless. Auto-deletion of expired or rotated-out credentials is bounded by an owner-tag scheme — the reconciler will only ever touch entities the plugin itself created.

## Documents

- [`docs/techrfc.md`](docs/techrfc.md) — formal RFC: requirements, API, risks, open questions
- [`docs/design.md`](docs/design.md) — companion design doc with detailed examples and rationale
- [`docs/decisions.md`](docs/decisions.md) — non-obvious design choices and why

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
