# State-Assumption Findings — Verification Report (2026-05-31)

Each finding: verdict (REAL / REFUTED / DOCUMENTED-RISK), artifact (test path or static proof), action.

| # | Finding | Verdict | Artifact | Action |
|---|---------|---------|----------|--------|
| F1 | Reconciler ConfirmationHold guard dead (6 plugins) | REAL | static: reconciler.go:62 gated on CreatedAt, no lister sets it | fix (Task 3,4) |
| F2 | GCP/OVH no HTTP client timeout | REAL | static: http.DefaultClient at iam_client.go + token_client.go | fix (Task 8) |
| F3 | OCI fakeOCIClient unsynchronized map | TBD | Task 2 | — |
| F4 | OCI rotation-vs-reconcile delete race | TBD | Task 2 | — |
| F5 | Reconciler DeleteEntity not 404-idempotent (5 plugins) | TBD | Task 6 | — |
| F6 | Create-then-track: untracked live cred on Put failure | TBD | Task 7 | — |
| F7 | Azure addPassword Graph propagation lag | TBD | Task 9 | — |
| F8 | pkg/worker tests sleep-based / flaky | REAL | static: worker_test.go fixed sleeps + [4,6] band | fix (Task 10) |

## Notes
(Subsequent tasks append per-finding detail here.)

### F1 — Reconciler ConfirmationHold guard is dead code
The guard lives at `pkg/reconciler/reconciler.go:62`: `if r.config.ConfirmationHold > 0 && !entity.CreatedAt.IsZero() {` (with the age comparison at line 63 `if now.Sub(entity.CreatedAt) < r.config.ConfirmationHold {`). `UpstreamEntity.CreatedAt` is declared at reconciler.go:11. All six listers construct `reconciler.UpstreamEntity{...}` setting ONLY `ID` and `Name`, never `CreatedAt`: credential-do reconciler_integration.go:26-29 (ID=t.ID, Name=t.Name), credential-azure:29-32 (ID=pw.KeyID, Name=pw.DisplayName), credential-vultr:26-29 (ID=u.ID, Name=u.Name), credential-exoscale:26-29 (ID=k.KeyID, Name=k.Name), credential-upcloud:26-29 (ID=t.ID, Name=t.Name), credential-akamai:26-29 (ID=c.ClientID, Name=c.ClientName). Since `CreatedAt` is always the zero value, `!entity.CreatedAt.IsZero()` is always false, so the ConfirmationHold branch is unreachable. Verdict: REAL.

### F2 — GCP/OVH lack client-side HTTP timeout
GCP issues requests via `http.DefaultClient.Do(req)` at `plugins/credential-gcp/iam_client.go:156` and `:208`; OVH via `http.DefaultClient.Do(req)` at `plugins/credential-ovh/token_client.go:63`. `http.DefaultClient` has no `Timeout` set, so a hung upstream can block indefinitely. By contrast DO (representative of the other 7 plugins) builds its client with an explicit timeout: `plugins/credential-do/do_client.go:13-14` defines `const httpTimeout = 30 * time.Second` and lines 48-49 construct `&http.Client{ Timeout: httpTimeout }`. Verdict: REAL.
