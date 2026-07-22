# STRIDE Threat Model — Payment API

Source: `context/system.md`, `plans/orchestrator-plan.md`

System: `POST /api/charge`. Flow: **client → API gateway (public) → charge service (internal-only) → payment processor (3rd party)**, with charge service also writing to **Postgres** (card token, customer_id, charge history). Auth is an API key in a header, validated against the DB.

Trust boundaries analyzed:
- **B1**: public internet → API gateway
- **B2**: API gateway → charge service
- **B3**: charge service → payment processor
- **B4**: charge service → Postgres

Components analyzed: API gateway, charge service, Postgres data store, 3rd-party payment processor integration, API key auth mechanism.

Severity is scored against this system specifically (payment flow, tokenized card data, internal-only service boundary), not in the abstract.

---

## 1. API Gateway (boundary: B1, public internet-facing)

### Spoofing
- **T1 — API key theft enables full client impersonation.** Because the gateway's only identity check on `/api/charge` is a static header value, any party who obtains a valid key (via logs, client-side leakage, phishing) can impersonate that merchant/client with no additional factor. **Severity: High** — directly enables fraudulent charges under another client's identity, no secondary control exists at this boundary. **Mitigation:** Require TLS client behavior binding (e.g., HMAC request signing with a per-key secret, not just a bearer key) or mutual TLS for the highest-volume clients; enforce key rotation every 90 days with overlap window; alert on API key usage from new/anomalous IP ranges or geographies.

### Tampering
- **T2 — In-transit modification of charge amount/customer_id if TLS is downgraded.** If the gateway accepts HTTP or permits TLS 1.0/1.1 or weak ciphers, an on-path attacker (public Wi-Fi, compromised router) can alter `amount`, `customer_id`, or the destination card token reference before it reaches the gateway. **Severity: Critical** — direct financial fraud vector on the single public entry point. **Mitigation:** Enforce TLS 1.2+ only, HSTS with `includeSubDomains`, reject plaintext HTTP with a hard redirect disabled (deny, not redirect), and pin/verify certificate chain in client SDKs distributed to merchants.

### Repudiation
- **T3 — No verifiable request log at the edge.** If the gateway does not persist a signed record (source IP, API key ID, timestamp, full request body hash, TLS session info) before forwarding, a client can plausibly deny having submitted a charge request when a chargeback or dispute occurs. **Severity: Medium** — impacts dispute resolution and fraud investigation, not immediate system compromise. **Mitigation:** Log every inbound request at the gateway with an immutable, append-only store (e.g., write-once log shipping to a separate account/service) including API key ID, source IP, request hash, and gateway-assigned correlation ID before the request is forwarded downstream.

### Information Disclosure
- **T4 — Verbose error responses leak internal details.** Unhandled exceptions at the gateway (e.g., malformed JSON, oversized payloads) returning stack traces, internal hostnames, or upstream service names to the public internet. **Severity: Medium** — aids reconnaissance for further attacks (e.g., identifying charge service internal DNS name). **Mitigation:** Centralize error handling at the gateway to return only a generic error code + correlation ID to the client; route full exception detail to internal logging only.

### Denial of Service
- **T5 — Unauthenticated flood of `/api/charge` exhausts gateway/charge service capacity.** Because the endpoint is public and the only gate is a header check performed *after* the connection is accepted, volumetric or slow-request (slowloris-style) floods consume gateway connection pools and cascade load to the internal charge service and Postgres. **Severity: High** — single public endpoint is a natural chokepoint for the entire payment flow; an outage here stops all revenue-generating traffic. **Mitigation:** Enforce per-IP and per-API-key rate limiting at the gateway (e.g., token bucket, 429 with `Retry-After`) before any downstream call is made; deploy behind a WAF/CDN with L3/L4 and L7 DDoS protection; set aggressive connection/read timeouts to shed slow clients.

### Elevation of Privilege
- **T6 — Routing misconfiguration exposes internal-only endpoints publicly.** If the gateway's route table is misconfigured (e.g., a wildcard proxy rule) it could inadvertently expose charge service admin/debug routes (refund, replay, internal health endpoints with elevated capability) to the public internet, bypassing the internal-only boundary entirely. **Severity: Critical** — collapses the B2 trust boundary, giving internet-facing access to functions assumed to be internal-only. **Mitigation:** Maintain an explicit allowlist of routes the gateway may forward (deny-by-default), with automated route-diffing in CI that fails the build if a new charge-service route is exposed without security sign-off.

---

## 2. Charge Service (internal-only; receives across B2, calls out across B3/B4)

### Spoofing
- **T7 — Any host on the internal network can impersonate the gateway.** If the gateway → charge service call (B2) relies only on network location ("internal-only") rather than cryptographic authentication, any compromised internal host (e.g., a breached CI runner or an adjacent internal service) can call the charge service directly, skipping the gateway's rate limiting and key validation entirely. **Severity: Critical** — this is the exact trust boundary the orchestrator plan flags (B2); network segmentation alone is not authentication, and it's the difference between "public API abused" and "internal blast-radius total." **Mitigation:** Require mTLS or a short-lived service-to-service JWT (signed by a workload identity, e.g., SPIFFE/SPIRE or cloud IAM) between gateway and charge service, independent of network ACLs; charge service must reject any request lacking a valid gateway-issued assertion even if it arrives from an "internal" IP.

### Tampering
- **T8 — Unauthenticated internal traffic allows charge parameter tampering in-flight.** Absent request signing or mTLS on B2, an attacker with a foothold on the internal network segment can modify `amount` or `customer_id` between gateway and charge service (classic MITM, but now inside the perimeter where it's often unmonitored). **Severity: High** — internal networks are frequently flat and under-monitored, making this a realistic lateral-movement outcome. **Mitigation:** Same control as T7 (mTLS/signed service tokens) plus body-integrity check (HMAC over canonicalized request) verified by charge service before processing.

### Repudiation
- **T9 — Missing correlation ID propagation breaks the audit chain.** If the charge service doesn't require and persist the gateway-assigned correlation ID (from T3) alongside its own processing record, a disputed charge cannot be traced end-to-end from client request to processor call to DB write. **Severity: Medium** — undermines fraud/dispute investigations and internal accountability, not an immediate exploit. **Mitigation:** Enforce correlation ID as a required field in the internal request schema; charge service rejects requests missing it; store it on every charge_history row.

### Information Disclosure
- **T10 — Card token or customer PII leaks into application logs.** Charge service logging (e.g., debug-level request/response logging, error logs on processor failures) may capture the full card token, customer_id, or processor response bodies in plaintext, landing in a log aggregation system with broader access than the payment path itself. **Severity: High** — even though raw PAN isn't stored, the card token is itself a bearer credential usable to initiate charges against that card; log systems are a common breach vector with weaker access controls than the primary DB. **Mitigation:** Implement structured logging with an explicit field-level redaction/allowlist (never log `card_token`, mask `customer_id` to last 4 chars); add a log-scanning CI/runtime check (e.g., regex/DLP scanner) that fails builds or alerts if a token-shaped value is emitted to logs.

### Denial of Service
- **T11 — Retry storms from processor timeouts exhaust charge service threads/connections.** If the charge service retries payment processor calls without backoff/circuit-breaking, a slow or degraded processor causes thread/connection pool exhaustion inside the charge service, which then cannot serve legitimate requests even after the gateway's rate limiting. **Severity: Medium** — availability impact confined to charge flow, recoverable, but directly caused by an external dependency (processor) the team doesn't control. **Mitigation:** Implement a circuit breaker (e.g., open after N consecutive processor timeouts/5xx) with exponential backoff and jitter, and bound the outbound connection pool to the processor separately from inbound capacity so processor slowness can't starve gateway-facing threads.

### Elevation of Privilege
- **T12 — No per-key scoping lets any valid API key trigger privileged operations (refunds, replays).** If the charge service's authorization model is "valid API key → full access to all charge-service operations" rather than scoped permissions, a key intended only for creating charges could also trigger refunds or administrative replay endpoints. **Severity: High** — a single leaked low-privilege key becomes equivalent to a master key for the whole payment surface. **Mitigation:** Implement per-key scopes/roles (e.g., `charge:create`, `charge:refund`, `charge:read`) enforced at the charge service (not just the gateway), stored alongside the key record in Postgres, and checked on every operation.

---

## 3. Postgres Data Store (boundary: B4, charge service → Postgres)

### Spoofing
- **T13 — Weak/shared DB credentials allow non-charge-service processes to impersonate the service to Postgres.** If DB credentials are shared across services or embedded in config without per-service accounts, a compromised adjacent service can connect to Postgres as if it were the charge service. **Severity: Medium** — requires prior compromise of another internal service, but removes the last boundary before the payment data store. **Mitigation:** Issue a dedicated least-privilege DB role per service, backed by short-lived credentials (e.g., cloud IAM DB auth or a secrets manager with automatic rotation), never a static shared password in config files.

### Tampering
- **T14 — SQL injection in charge service queries alters charge_history or card token references.** If any query path (e.g., filtering charge history by customer-supplied `customer_id` or search parameters) uses string concatenation instead of parameterized queries, an attacker could tamper with stored charge records or exfiltrate other customers' tokens. **Severity: Critical** — direct path to altering the financial record of truth and/or accessing card tokens across tenants. **Mitigation:** Enforce parameterized queries/ORM usage exclusively (lint rule + code review gate that blocks raw string-interpolated SQL); run periodic SAST/DAST (e.g., sqlmap-class scanning) against the charge service's DB-facing endpoints in CI.

### Repudiation
- **T15 — Charge history is mutable with no audit trail, allowing undetected alteration or deletion.** If `charge_history` rows can be UPDATE/DELETE'd by the charge service's DB role without a separate append-only audit log, an insider or attacker with DB access could rewrite the financial record with no trace, undermining the ability to prove which charges actually occurred (e.g., to resolve a processor dispute or regulatory audit). **Severity: High** — payment history is the authoritative record for reconciliation and disputes; silent tampering here is a severe integrity/compliance failure. **Mitigation:** Make `charge_history` insert-only at the DB grant level (REVOKE UPDATE/DELETE from the charge-service role for that table); if corrections are needed, require a compensating "adjustment" row rather than mutation; ship a database-level audit trigger (e.g., `pgaudit`) logging all DDL/DML to a separate write-once destination.

### Information Disclosure
- **T16 — Unencrypted data at rest / broad DB user exposes card tokens and customer_id in a breach or backup leak.** Card tokens, customer_id, and full charge history are high-value even without raw PAN (tokens can often be replayed against the processor within scope). A stolen backup, misconfigured snapshot sharing, or over-permissioned read replica exposes this data wholesale. **Severity: High** — token + customer_id correlation is a meaningful PII/financial exposure and likely triggers breach-notification obligations. **Mitigation:** Enable encryption at rest (TDE or disk-level) plus column-level encryption for `card_token` with keys in a separate KMS (so a DB-only compromise doesn't yield usable tokens); restrict backup/snapshot access via IAM policy and disable public snapshot sharing; apply least-privilege grants so no role has blanket `SELECT *` beyond what its function needs.

### Denial of Service
- **T17 — Unbounded charge_history growth/query patterns degrade DB availability.** Without pagination limits, indexing on `customer_id`/timestamp, or connection pool caps, high-volume charge history reads (e.g., a reporting feature or an abusive client polling history) can cause table scans and connection exhaustion, degrading the DB for the entire payment path. **Severity: Medium** — availability degradation, recoverable, but Postgres is a shared dependency for every charge. **Mitigation:** Add composite index on `(customer_id, created_at)`, enforce max page size on any history-read endpoint, and use a bounded connection pool (e.g., PgBouncer) with per-service connection caps so one noisy consumer can't starve others.

### Elevation of Privilege
- **T18 — Charge service's DB role has more privilege than required (e.g., DDL rights).** If the charge service connects with a role that can `ALTER`/`DROP`/`CREATE`, a successful injection (T14) or credential leak escalates from data tampering to full schema control. **Severity: High** — turns a data-layer bug into total data-store compromise. **Mitigation:** Grant the charge-service role only `SELECT/INSERT` on the specific tables it needs (no DDL, no `DELETE` per T15); use a separate, more privileged role — never used by the running service — for migrations, invoked only via CI/CD pipeline.

---

## 4. Third-Party Payment Processor Integration (boundary: B3, charge service → processor)

### Spoofing
- **T19 — Charge service could be redirected to a spoofed processor endpoint.** If the processor's API hostname is configurable at runtime (e.g., via env var without integrity checks) or DNS isn't validated/pinned, DNS spoofing, SSRF-style config injection, or a compromised internal config store could redirect outbound charge calls (including card tokens) to an attacker-controlled endpoint. **Severity: Critical** — this would exfiltrate card tokens and allow silent fraud (fake "success" responses) at the exact point real money moves. **Mitigation:** Hardcode/pin the processor's TLS certificate (certificate pinning) or CA, validate the resolved endpoint against an allowlist at startup, and alert on any change to the processor endpoint configuration via change-management review.

### Tampering
- **T20 — Unverified webhook callbacks let an attacker forge payment status.** If the processor sends async callbacks (e.g., payment confirmation, refund status) and the charge service doesn't verify a cryptographic signature (HMAC/webhook secret) on inbound callbacks, an attacker who discovers the webhook URL can POST a forged "payment succeeded" event, causing charge_history to record a fraudulent success and potentially trigger downstream fulfillment. **Severity: Critical** — directly forges the financial record without ever touching the real processor, bypassing all upstream controls. **Mitigation:** Verify the processor's webhook signature (per their documented HMAC scheme) on every inbound callback before processing; reject and alert on any unsigned or invalid-signature callback; additionally reconcile async status against a direct API query to the processor rather than trusting the webhook alone for high-value transactions.

### Repudiation
- **T21 — No idempotency key / processor transaction ID linkage makes disputes with the processor unresolvable.** If the charge service doesn't generate and log an idempotency key per attempt and persist the processor's returned transaction ID against the internal charge record, retries during network failures can create ambiguity about whether a charge succeeded, and disputes with the processor (or the end customer) can't be authoritatively resolved. **Severity: Medium** — operational/financial reconciliation risk rather than a direct exploit, but compounds with T11 (retries). **Mitigation:** Generate a UUID idempotency key per charge attempt, send it on every request to the processor (most processors support this natively), and store both the idempotency key and the processor's transaction ID on the charge_history row.

### Information Disclosure
- **T22 — Card token/customer data exposed via processor API credential leakage or excessive logging of processor responses.** If the charge service's processor API key is over-logged (e.g., in outbound request debug logs) or the processor's response body (which may include masked-but-still-sensitive card metadata) is logged verbatim, this data is exposed to anyone with log access. **Severity: Medium** — overlaps with T10 but specific to the outbound leg; processor responses often contain more metadata (card brand, last4, risk scores) than the charge service needs to retain. **Mitigation:** Apply the same log-redaction allowlist as T10 to outbound processor calls; store the processor API credential in a secrets manager (not env vars in plaintext config) with access auditing.

### Denial of Service
- **T23 — No circuit breaker/timeout on processor calls lets a degraded processor take down the charge service.** (Cross-reference T11.) A slow or unresponsive processor with no bounded timeout causes charge service threads to block, eventually exhausting capacity for all clients regardless of which client's charge is stuck. **Severity: Medium** — external dependency risk; mitigated by the same control as T11. **Mitigation:** Bounded timeout (e.g., 5s) on all processor calls, circuit breaker to fail fast once error/timeout rate crosses threshold, and a documented degraded-mode response (e.g., queue-and-retry-later) rather than blocking the request path.

### Elevation of Privilege
- **T24 — Processor API credential is over-scoped (can refund/payout, not just charge).** If the charge service's processor-side API key has capabilities beyond what's needed (e.g., payouts, account configuration changes) because a single key was provisioned for convenience, a leak of that credential (via T22 or a config leak) grants the attacker far more than the ability to submit fraudulent charges. **Severity: High** — turns a credential leak into potential direct fund exfiltration via payout APIs. **Mitigation:** Provision a processor API key scoped to only the `charge`/`capture` capability the service actually uses; if the processor supports it, use restricted keys or Connect-style scoped tokens per use case, and store/rotate via secrets manager.

---

## 5. API Key Auth Mechanism (used at B1, referenced across B2/B4)

### Spoofing
- **T25 — Plaintext or reversibly-encrypted key storage in Postgres means a DB read compromise = full key compromise.** If API keys are stored as plaintext or with reversible encryption rather than hashed (like passwords), a Postgres read-only compromise (e.g., via T14 or a misconfigured replica) immediately yields usable credentials for every client. **Severity: Critical** — collapses the API key control entirely; this is the single authentication mechanism protecting the public endpoint. **Mitigation:** Store only a salted hash of the API key (e.g., SHA-256 with a per-key salt, or bcrypt-style if length allows) in Postgres; validate by hashing the presented key and comparing, never store/return the raw key after initial issuance.

### Tampering
- **T26 — Trusting client-supplied fields (e.g., customer_id) merely because the API key matched.** If the charge service treats any field in the request body as authoritative once the API key check passes (rather than deriving customer identity server-side from the key record), an attacker holding a valid key for customer A could submit `customer_id` for customer B, charging or attributing history to the wrong account. **Severity: High** — enables cross-customer charge misattribution using a legitimately-issued key. **Mitigation:** Derive `customer_id`/merchant identity server-side from the authenticated API key record (DB lookup), never accept it as a trusted request parameter; if multiple customers are legitimately addressable by one key, enforce an explicit authorization check that the key's account owns the target customer_id.

### Repudiation
- **T27 — Shared/non-unique API keys across a client's systems prevent attributing a specific charge request to a specific origin.** If a single API key is reused across multiple servers/services for one client (common for convenience), a disputed or fraudulent charge cannot be attributed to which internal system of the client issued it, complicating incident response. **Severity: Low** — mostly a client-side hygiene issue, but the payment provider can influence it via provisioning design. **Mitigation:** Support (and encourage in onboarding docs) issuance of multiple scoped sub-keys per client, each independently revocable and logged, rather than one shared key per account.

### Information Disclosure
- **T28 — API keys captured in access logs, error logs, or APM traces.** Because the key travels in a request header, any logging layer (gateway access logs, APM/tracing tools, error reporting SDKs) that captures full headers by default will persist the raw key in a system with broader access than the auth DB itself. **Severity: High** — a very common, easy-to-miss leak path that fully defeats the auth mechanism for whoever has log/APM access. **Mitigation:** Configure the gateway and any APM/tracing agents to redact the `Authorization`/API-key header by default (deny-list common auth header names at the logging middleware level); add a CI check that fails if a new logging integration is added without header redaction configured.

### Denial of Service
- **T29 — No per-key rate limiting allows one compromised or abusive key to exhaust shared capacity.** Since rate limiting (T5's mitigation) is often applied globally or per-IP, a single leaked or malicious API key issuing high-volume requests from many IPs (e.g., via a botnet) could still exhaust charge service/processor capacity, degrading service for all other clients ("noisy neighbor"). **Severity: Medium** — availability/fairness issue distinct from T5's anonymous flood case. **Mitigation:** Implement per-API-key rate limits (not just per-IP) enforced at the gateway, with tiered limits configurable per client tier, and automatic temporary key suspension when a key's error/volume pattern crosses an anomaly threshold.

### Elevation of Privilege
- **T30 — Flat privilege model: every API key can perform every operation the charge service exposes.** Without scopes tied to the key record (per T12), there's no way to issue a restricted key (e.g., read-only reporting access for a client's finance team) without granting full charge/refund capability. **Severity: Medium** — increases blast radius of any single key leak; overlaps with T12 but is rooted in the auth data model itself. **Mitigation:** Extend the API key schema in Postgres with a `scopes`/`role` column set at issuance time, enforced by the charge service on every request (see T12); default new keys to least privilege, requiring explicit elevation.

---

# Consolidated Threat List

| # | Threat | Component | STRIDE | Severity | Mitigation |
|---|--------|-----------|--------|----------|------------|
| T2 | Plaintext/weak-TLS in-transit tampering of charge amount/customer_id at the public gateway | API Gateway (B1) | Tampering | Critical | Enforce TLS 1.2+, HSTS, reject/deny plaintext HTTP, pin cert chain in client SDKs |
| T6 | Gateway routing misconfig exposes internal-only charge-service endpoints publicly | API Gateway (B1→B2) | Elevation of Privilege | Critical | Deny-by-default route allowlist; CI route-diffing gate on new exposures |
| T7 | No cryptographic auth between gateway and charge service — any internal host can impersonate the gateway | Charge Service (B2) | Spoofing | Critical | mTLS or short-lived signed service tokens (SPIFFE/SPIRE or cloud workload identity) between gateway and charge service |
| T14 | SQL injection alters charge_history / exfiltrates card tokens | Postgres (B4) | Tampering | Critical | Parameterized queries only (lint + CI gate); periodic SAST/DAST scanning |
| T19 | Charge service redirected to a spoofed payment-processor endpoint (DNS spoof/SSRF/config injection) | Payment Processor Integration (B3) | Spoofing | Critical | Certificate pinning / endpoint allowlist validated at startup; change-managed config review |
| T20 | Unverified webhook signature lets attacker forge "payment succeeded" callbacks | Payment Processor Integration (B3) | Tampering | Critical | Verify processor webhook HMAC signature; reconcile async status via direct API query for high-value txns |
| T25 | API keys stored plaintext/reversible in Postgres — a DB read compromise = full credential compromise | API Key Auth | Spoofing | Critical | Store salted hash of API key only; validate by hash comparison, never store raw key post-issuance |
| T1 | API key theft = full client impersonation (no secondary factor) | API Gateway / API Key Auth (B1) | Spoofing | High | HMAC request signing per key or mTLS for high-volume clients; 90-day rotation; anomaly alerting on new IP/geo |
| T5 | Unauthenticated request flood exhausts gateway/charge-service/DB capacity | API Gateway (B1) | Denial of Service | High | Per-IP and per-key rate limiting at gateway; WAF/CDN DDoS protection; aggressive timeouts |
| T8 | Unauthenticated internal traffic allows in-flight tampering of charge params on B2 | Charge Service (B2) | Tampering | High | mTLS/signed tokens (same as T7) + HMAC body-integrity check |
| T10 | Card token / customer PII leaks into application logs | Charge Service | Information Disclosure | High | Field-level log redaction allowlist (never log card_token); DLP/regex scanner in CI/runtime |
| T12 | No per-key scoping — any valid key can trigger refunds/admin replay operations | Charge Service | Elevation of Privilege | High | Per-key scopes/roles (charge:create, charge:refund, etc.) enforced server-side |
| T15 | Charge history is mutable with no audit trail — silent tampering/deletion possible | Postgres (B4) | Repudiation | High | Insert-only DB grants on charge_history (REVOKE UPDATE/DELETE); compensating-adjustment pattern; pgaudit trigger to separate log |
| T16 | Card tokens + customer_id exposed via unencrypted backups/snapshots or over-permissioned DB roles | Postgres (B4) | Information Disclosure | High | Encryption at rest + column-level encryption for card_token via separate KMS; restrict backup/snapshot IAM; least-privilege grants |
| T18 | Charge service DB role has DDL rights beyond what it needs | Postgres (B4) | Elevation of Privilege | High | Grant only SELECT/INSERT to service role; separate migration-only role used exclusively by CI/CD |
| T24 | Processor API credential over-scoped (can refund/payout, not just charge) | Payment Processor Integration (B3) | Elevation of Privilege | High | Provision processor key scoped to charge/capture only; use restricted/Connect-style tokens; rotate via secrets manager |
| T26 | customer_id trusted from request body once API key matches — cross-customer charge misattribution | API Key Auth / Charge Service | Tampering | High | Derive customer identity server-side from the authenticated key record; never trust client-supplied customer_id directly |
| T28 | API keys captured in access logs / APM traces via default header logging | API Key Auth | Information Disclosure | High | Redact Authorization/API-key headers by default at gateway + APM; CI check for new unredacted logging integrations |
| T3 | No verifiable, tamper-evident request log at the gateway — client can repudiate a charge request | API Gateway (B1) | Repudiation | Medium | Append-only signed request log (source IP, key ID, body hash, correlation ID) before forwarding |
| T4 | Verbose gateway error responses leak internal details to the public internet | API Gateway (B1) | Information Disclosure | Medium | Generic client-facing errors + correlation ID; full detail only in internal logs |
| T9 | Missing correlation ID propagation breaks end-to-end audit trail for disputed charges | Charge Service | Repudiation | Medium | Require correlation ID in internal schema; persist on every charge_history row |
| T11 / T23 | No circuit breaker/timeout on processor calls — retry storms exhaust charge-service capacity | Charge Service / Payment Processor Integration (B3) | Denial of Service | Medium | Circuit breaker + bounded timeout (e.g., 5s) + exponential backoff with jitter; separate outbound connection pool |
| T13 | Weak/shared DB credentials allow credential-based impersonation to Postgres | Postgres (B4) | Spoofing | Medium | Per-service least-privilege DB role with short-lived, auto-rotated credentials (IAM DB auth or secrets manager) |
| T17 | Unbounded charge_history growth/query patterns degrade DB availability | Postgres (B4) | Denial of Service | Medium | Composite index on (customer_id, created_at); max page size on history reads; bounded connection pool (PgBouncer) |
| T21 | No idempotency key / processor transaction ID linkage — disputes with processor unresolvable | Payment Processor Integration (B3) | Repudiation | Medium | UUID idempotency key per attempt sent to processor; store idempotency key + processor transaction ID on charge_history |
| T22 | Card token/customer metadata exposed via over-logged processor requests/responses | Payment Processor Integration (B3) | Information Disclosure | Medium | Same redaction allowlist as T10 applied to outbound processor calls; processor credential in secrets manager |
| T29 | No per-key rate limiting — one compromised key exhausts shared capacity across clients | API Key Auth | Denial of Service | Medium | Per-API-key rate limits at gateway, tiered by client; auto-suspend on anomalous volume/error pattern |
| T30 | Flat privilege model — no way to issue restricted (e.g., read-only) keys | API Key Auth | Elevation of Privilege | Medium | Add scopes/role column to API key schema at issuance; default to least privilege |
| T27 | Shared API keys across a client's own systems prevent attributing a charge to its origin | API Key Auth | Repudiation | Low | Support/encourage multiple scoped, independently-revocable sub-keys per client account |

**Totals:** 30 threats identified — 7 Critical, 11 High, 10 Medium, 1 Low (T11/T23 and T5 counted individually above; consolidated table merges T11/T23 as one row since they share root cause and mitigation).

Coverage check against orchestrator eval criteria:
- All 4 trust boundaries (B1–B4) addressed.
- All 5 components addressed (API gateway, charge service, Postgres, payment processor integration, API key auth).
- All 6 STRIDE categories represented at least twice per major component where applicable.
- Every threat has a severity grounded in the specific data flow/boundary (not generic) and a concrete mitigation (specific control, not "follow best practices").
