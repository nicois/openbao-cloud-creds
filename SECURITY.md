# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately by opening a GitHub **security advisory**
on this repository (Security → Advisories → Report a vulnerability). Please do not
open a public issue for anything exploitable.

Include, as far as you can: the affected plugin or `pkg/` package, the privilege a
reporter needs to reach it, and what an attacker gains. Reproduction against a cloud
fake (`pkg/credenvelope/fakes/`) is more useful than against a real account, and does
not require credentials.

We will acknowledge within a week and tell you whether we consider it in scope.

## What this software is, in threat terms

These are OpenBao secrets-engine plugins. Each holds one or more long-lived **minter**
credentials for a cloud provider and uses them to issue short-lived, role-scoped
credentials to callers. So:

- **A minter credential is the highest-value secret at rest.** Anything that lets a
  caller read one, redirect a request carrying one, or cause one to be sent somewhere
  unexpected is in scope and serious. Configuration-write privilege is *not* meant to
  be equivalent to minter-read privilege; a path that makes it so is a vulnerability.
- **The owner-tag scheme is load-bearing.** The reconciler may delete upstream cloud
  credentials. Anything that widens what it will delete — beyond entities this mount
  created — is in scope, including a way to make an entity *look* owned.
- **Issued credentials must not outlive their lease** (techrfc OBC-002), and a lease
  must not outlive its credential. Either direction is in scope.
- **Error responses must not carry upstream response bodies** to API callers; cloud
  diagnostics go to the operator's log. A leak of upstream detail to a lower-privileged
  caller is in scope.

## Explicitly out of scope

- **`credential-do` cannot issue against real DigitalOcean.** DO refuses token
  management for every personal access token at its edge gateway; see
  `docs/known-issues.md` (KI-009). This is a fact about DigitalOcean, not a
  vulnerability here.
- **`credential-oci` is experimental**: its production client is unimplemented stubs.
- **Metrics do not reach an operator** unless the plugins are compiled into a custom
  OpenBao build as builtins; see A12 in `docs/audit-2026-08-22.md`. Documented, not a
  vulnerability.
- Findings that require an operator to have already been given credentials they should
  not have, or to run a build they did not verify.

## Verifying what you run

`make dist` produces the plugin binaries and a `SHA256SUMS`. Verify the hash before
registering, and register with it:

```
bao plugin register -sha256=<hash> -command=credential-aws secret cloud-creds-aws
```

OpenBao refuses to run a plugin whose hash does not match, which is the control that
makes the rest of this policy meaningful.

## Known audit state

`docs/audit-2026-08-22.md` records a three-lens audit with per-finding status. Open
items are listed there rather than hidden; anything security-relevant and still open
carries `[OPEN]`.
