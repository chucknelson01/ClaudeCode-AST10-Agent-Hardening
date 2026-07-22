# Orchestrator Decision — Merged Threat Model

System: Payment API (`context/system.md`). Inputs: `plans/stride-plan.md` (30 threats, component-by-component) and `plans/attack-tree-plan.md` (32 threats, goal-down from 5 attacker objectives).

## Coverage check against orchestrator-plan.md eval criteria

| Criterion | STRIDE | Attack-tree |
|---|---|---|
| All 4 trust boundaries addressed | Yes | Yes |
| All components addressed | Yes (gateway, charge service, Postgres, processor, API-key auth as a 5th "component") | Yes (same, folded into goal trees) |
| Actionable, specific mitigations | Yes, no generic advice | Yes, no generic advice |
| Severity grounded in the actual data flow | Yes | Yes |
| **Predicted blind spot confirmed?** | Missed multi-step/chained attacks — confirmed: no RCE/pivot chain, no SSRF, no supply-chain, no business-logic/race-condition threats | Missed systemic repudiation/audit gaps — confirmed: no request-log integrity, no charge_history mutability, no correlation-ID / dispute-trail findings |

Net: the two models overlap heavily on the "obvious" critical issues (API key storage, SQL injection, B2 trust boundary, webhook forgery, in-transit tampering) but are genuinely complementary at the edges. Neither alone is sufficient.

## The 10 fixes that close the most threats

Ranked by how many deduplicated threats each mitigation resolves or substantially mitigates — fix these first regardless of team size:

1. **Hash API keys (salted hash, never plaintext/reversible) in Postgres.** Closes STRIDE T25, AT #3; reduces blast radius of STRIDE T1, AT #8.
2. **mTLS or signed short-lived service tokens on B2 (gateway → charge service), independent of network location.** Closes STRIDE T7/T8, AT #22/#23. This is the single most-cited finding across both models — treat "internal network" as zero authentication value.
3. **Parameterized queries everywhere + least-privilege DB role (no DDL/DELETE) for the charge service.** Closes STRIDE T14/T18, AT #1.
4. **TLS 1.2+ enforced end-to-end, including internal hops, with cert pinning on client SDKs.** Closes STRIDE T2, AT #9/#10/#15/#23.
5. **Verify payment-processor webhook signatures on every inbound callback; reconcile high-value transactions via direct API query.** Closes STRIDE T20, AT #12.
6. **Secrets manager + rotation for DB and processor credentials; network ACL restricting Postgres to the charge service only.** Closes STRIDE T13/T16/T22/T24, AT #2/#13/#16.
7. **Server-side validation of amount/currency, idempotency keys, DB-level unique constraints on (customer_id, order_reference).** Closes AT #9/#11/#24 — business-logic gaps STRIDE's component-by-component pass never surfaced.
8. **Dependency/image scanning + patch SLA + non-root minimal-privilege runtime for gateway and charge service.** Closes AT #4/#5/#6/#7 — RCE, SSRF, deserialization, supply-chain. STRIDE has no equivalent finding at all.
9. **Deny-by-default route allowlist at the gateway with CI diffing.** Closes STRIDE T6.
10. **Tamper-evident audit trail: append-only signed request log at the gateway, required correlation ID, insert-only `charge_history` grants (REVOKE UPDATE/DELETE).** Closes STRIDE T3/T9/T15/T21 — repudiation gaps the attack-tree model structurally can't surface (it reasons from attacker goals, not from "can we prove what happened after the fact").

## Deduplicated Critical threats (both models, merged)

| Threat | Source(s) | Mitigation owner |
|---|---|---|
| API keys stored plaintext/reversible in Postgres | STRIDE T25 (Critical), AT #3 (Critical) | Auth/platform team — fix #1 |
| SQL injection in charge-service DB access | STRIDE T14 (Critical), AT #1 (Critical) | Charge service team — fix #3 |
| B2 has no independent auth, network-location trust only | STRIDE T7 (Critical), AT #22/#5.4.1 (High), AT #23/#1.3.2 (Medium) | Platform/infra — fix #2 |
| Postgres credentials leaked → direct DB access bypassing app | AT #2 (Critical) | Infra/secrets — fix #6 |
| Payment processor endpoint spoofed/redirected (DNS/SSRF/config injection) | STRIDE T19 (Critical) | Charge service team — cert pinning + endpoint allowlist |
| Unverified webhook signature forges "payment succeeded" | STRIDE T20 (Critical), AT #12 (High) | Charge service team — fix #5 |
| Gateway RCE via unpatched dependency, pivot to charge service | AT #4 (Critical) | Platform/infra — fix #8 |
| SSRF in gateway reaches internal-only services | AT #5 (Critical) | Gateway team — fix #8 |
| Insecure deserialization in charge service → RCE | AT #6 (Critical) | Charge service team — fix #8 |
| Supply-chain compromise of a dependency | AT #7 (Critical) | Platform/infra — fix #8 |
| Gateway routing misconfig exposes internal-only endpoints | STRIDE T6 (Critical) | Gateway team — fix #9 |
| TLS downgrade allows in-transit tampering of amount/customer_id | STRIDE T2 (Critical), AT #10 (High) | Gateway team — fix #4 |

## Deduplicated High threats (merged, condensed)

| Threat | Source(s) |
|---|---|
| Stolen/leaked static API key → full impersonation, no second factor | STRIDE T1, AT #8 (rated Critical/High in AT) |
| Replay of a captured legitimate charge request (no key theft needed) | AT #9 — **STRIDE blind spot** |
| Malformed/negative/overflow amount bypasses validation before reaching processor | AT #11 — **STRIDE blind spot** |
| Postgres exposed to broader network than intended (misconfig) | AT #13, related to STRIDE T13 (Medium) |
| IDOR: valid key reads another customer's charge history | AT #14 — **STRIDE blind spot** |
| Card token/PII leaked into application or gateway logs | STRIDE T10, AT #26 |
| Compromised processor-side credentials expose full transaction history | STRIDE T24 (over-scoping angle), AT #16 (credential-theft angle) |
| No per-key scoping — any key can trigger refunds/admin ops | STRIDE T12 — **attack-tree blind spot** (AT never modeled refund abuse) |
| Charge history mutable, no audit trail | STRIDE T15 — **attack-tree blind spot** |
| Unauthenticated flood exhausts gateway/charge-service/DB capacity | STRIDE T5, AT #18 |
| Command/template injection in charge-service code path | AT #21 — **STRIDE blind spot** |
| Processor account throttled/suspended via abusive charge attempts | AT #20 — **STRIDE blind spot** |
| customer_id trusted from request body once key matches (cross-customer misattribution) | STRIDE T26 |
| API keys captured in access logs / APM traces | STRIDE T28 |
| Static key embedded in client-distributed code | AT #17 |

Medium and Low items (rate limiting granularity, brute-force/timing side-channels, social engineering of support staff, race conditions on duplicate charges, log/backup hygiene, DoS via expensive payloads, unindexed queries) are fully enumerated with mitigations in `plans/stride-plan.md` and `plans/attack-tree-plan.md` — not duplicated here since neither model disputes the other's severity call on these, and they don't change the fix-first priority above.

## Bottom line

The two models agree the payment flow's single biggest structural weakness is treating **network location as authentication** at the gateway→charge-service boundary (B2) and treating the **API key as a bearer secret with no hashing, scoping, or rotation**. Fix #1–#3 above before anything else; they're cheap, well-understood controls that collapse the highest-severity findings from both models simultaneously. Fix #8 (dependency/patch hygiene) is the one category STRIDE's component-by-component method structurally cannot find — don't skip it just because it didn't show up in that report.
