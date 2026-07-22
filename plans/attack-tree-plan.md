# Attack Tree — Payment API

Goal-down attack tree analysis of the Payment API described in `context/system.md` and
`plans/orchestrator-plan.md`.

**System recap:**
`client -> API gateway (public) -> charge service (internal-only) -> payment processor (3rd party)`,
with the charge service also read/writing Postgres (card token, `customer_id`, charge history).
Auth is a static API key in a header, validated against the DB.

**Trust boundaries referenced throughout (from orchestrator-plan.md):**
- **B1**: public internet -> API gateway (untrusted -> semi-trusted)
- **B2**: API gateway -> charge service (semi-trusted -> internal-only)
- **B3**: charge service -> payment processor (internal -> external 3rd party)
- **B4**: charge service -> Postgres (internal -> data store)

Nodes marked **[OR]** succeed if any one child succeeds. Nodes marked **[AND]** require all
children to succeed. Leaves carry `Severity` and `Mitigation`.

---

## Root Goal 1: Make Unauthorized Charges

Attacker causes a charge to be created/settled without legitimate authorization from the
cardholder or account owner.

- **1. Make Unauthorized Charges [OR]**
  - **1.1 Forge or steal a valid API key, then call `POST /api/charge` directly [AND]** (see Root Goal 3 for the key-theft subtree; this node consumes that goal as a precondition)
    - 1.1.1 Use stolen/leaked key to submit charges against victim's stored card token
      - **Severity: Critical** — crosses B1 with full impersonation of a legitimate caller; charge service has no way to distinguish attacker from real client once the key validates.
      - **Mitigation**: Bind API keys to a specific customer/merchant scope + IP/CIDR allowlist or mTLS client cert in addition to the key; rate-limit and anomaly-detect on charge velocity per key (e.g., >N charges/min triggers step-up review or auto-suspend); require idempotency keys so replay of a captured request cannot double-charge.
  - **1.2 Replay a previously captured legitimate charge request (no key theft needed, just the request bytes) [OR]**
    - 1.2.1 Capture a valid `POST /api/charge` request (e.g., via unencrypted transport, logging leak, browser history/proxy) and resend it verbatim
      - **Severity: High** — crosses B1; does not require breaking the API key, only intercepting one authorized transaction.
      - **Mitigation**: Enforce TLS 1.2+ with HSTS on the gateway (reject plaintext); require a unique, server-checked `Idempotency-Key` per charge request, reject duplicates within a rolling window; sign requests with a per-request nonce/timestamp validated server-side (reject if >N seconds old or nonce already seen).
  - **1.3 Tamper with charge parameters in-flight (amount, customer_id, currency) between client and gateway or gateway and charge service [OR]**
    - 1.3.1 MITM at B1 (no/weak TLS enforcement, cert not pinned) to rewrite `amount` or `customer_id` before it reaches the gateway
      - **Severity: High** — crosses B1; directly falsifies the transaction the payment processor will settle.
      - **Mitigation**: TLS enforced end-to-end with HSTS + certificate validation on any client SDK; gateway rejects requests over plaintext; server-side revalidation of amount against a signed quote/invoice reference rather than trusting client-supplied amount alone where a prior quote exists.
    - 1.3.2 Tamper with the internal call from gateway to charge service (B2) if that link is plaintext HTTP inside the VPC
      - **Severity: Medium** — requires an attacker already positioned inside the network segment (B2 is "semi-trusted"), so likelihood is lower, but impact (forged internal charge calls) is high.
      - **Mitigation**: Require mTLS or a signed service-to-service token (e.g., short-lived JWT signed by gateway, verified by charge service) on the B2 hop; do not treat "internal network" as sufficient authentication.
  - **1.4 Exploit business logic in the charge service to bypass amount/limit checks [OR]**
    - 1.4.1 Negative amount, zero amount, integer overflow, or currency-mismatch injection to manipulate settlement or trigger refund-like behavior
      - **Severity: High** — crosses B3 (charge service -> payment processor); a malformed amount reaching the processor can cause miscredit or exploit processor-side rounding/currency bugs.
      - **Mitigation**: Strict server-side schema validation (positive integer minor-units, allow-listed currency codes, max-amount ceiling) before the charge service ever calls the processor; reject on any validation failure with no partial processing.
    - 1.4.2 Race condition: fire concurrent duplicate charge requests before the first one commits/dedupes, to bypass a "one charge per order" business rule
      - **Severity: Medium** — exploits a logic gap rather than a boundary crossing directly, but still results in real financial loss (duplicate settlement).
      - **Mitigation**: Enforce idempotency at the database layer with a unique constraint on `(customer_id, order_reference)` plus a DB-level transaction/row lock, not just an application-level check.
  - **1.5 Abuse a compromised/malicious payment processor callback or webhook to mark an unauthorized charge as "succeeded" [OR]**
    - 1.5.1 Forge a webhook callback from the "processor" back to the charge service (if the charge service trusts inbound processor callbacks without verifying signature)
      - **Severity: High** — crosses B3 in reverse; if unauthenticated, an attacker who merely knows the callback URL can fabricate settlement state, e.g., mark a fraudulent/free charge as paid.
      - **Mitigation**: Verify the processor's webhook signature (HMAC secret or public-key signature per the processor's SDK) on every inbound callback; reject unsigned or badly-signed callbacks; treat processor callbacks as untrusted input requiring full schema validation, same as any external request.

---

## Root Goal 2: Exfiltrate Customer / Charge Data

Attacker obtains card tokens, `customer_id` values, or charge history they should not have access to.

- **2. Exfiltrate Customer/Charge Data [OR]**
  - **2.1 Direct DB compromise (B4: charge service -> Postgres) [OR]**
    - 2.1.1 SQL injection via a charge service field (e.g., a free-text field passed through to a query without parameterization)
      - **Severity: Critical** — crosses B4 directly; full read/write access to card tokens, `customer_id`, and charge history.
      - **Mitigation**: Parameterized queries / ORM with no raw string concatenation anywhere charge-service code touches Postgres; add a SAST/CI rule that blocks string-built SQL; least-privilege DB role for the charge service (no `DROP`/`ALTER`, no access to unrelated tables).
    - 2.1.2 Credential exposure: Postgres connection string/password leaked (in a repo, log, error message, or environment dump) letting an attacker connect directly, bypassing the charge service entirely
      - **Severity: Critical** — crosses B4 without even needing the application layer.
      - **Mitigation**: Store DB credentials in a secrets manager (not env files in source control); rotate on any suspected exposure; network-level restriction so Postgres only accepts connections from the charge service's security group/subnet, not from the general internal network.
    - 2.1.3 Postgres itself exposed to a broader network than intended (misconfigured security group/firewall) allowing direct connection attempts from outside the internal segment
      - **Severity: High** — crosses B4 by skipping the charge service's access controls entirely.
      - **Mitigation**: Postgres bound to private subnet with security group allowing only the charge service host(s); no public IP; periodic automated config-drift scanning (e.g., cloud security posture tooling) to catch accidental exposure.
  - **2.2 Abuse the charge service's own API to enumerate/scrape data it's allowed to serve [OR]**
    - 2.2.1 IDOR: increment/guess `customer_id` or `charge_id` in a lookup endpoint to read other customers' charge history (assumes an endpoint beyond `/api/charge` exists for lookups, or that charge creation responses leak other customers' data)
      - **Severity: High** — crosses B1/B2; a valid-but-scoped API key used to pull data outside its own customer's scope.
      - **Mitigation**: Server-side authorization check that the authenticated key's associated `customer_id`/merchant scope matches the resource being requested on every read, not just on write; use non-sequential (UUID) identifiers for `charge_id` to prevent trivial enumeration as defense-in-depth (not a substitute for the authz check).
    - 2.2.2 No/weak rate limiting on lookup or charge-creation endpoints allows bulk scraping of card-token/charge-history data over many requests
      - **Severity: Medium** — crosses B1; slow-drip exfiltration rather than a single break-in, but same end state.
      - **Mitigation**: Per-key and per-IP rate limiting at the gateway with alerting on sustained elevated request rates; anomaly detection on read volume per key compared to that key's historical baseline.
  - **2.3 Intercept data in transit [OR]**
    - 2.3.1 Sniff traffic on B1 (client-gateway) or B2 (gateway-charge service) if TLS is absent/misconfigured, capturing card tokens or `customer_id` in request/response bodies
      - **Severity: High** — crosses B1 and/or B2; passive interception, no active exploitation needed.
      - **Mitigation**: TLS enforced on every hop including internal B2 traffic (do not assume internal network = safe); disable TLS 1.0/1.1 and weak ciphers at both gateway and internal load balancers.
    - 2.3.2 Card token or customer PII logged in plaintext (application logs, gateway access logs, error-tracking service) and those logs are exposed to a broader audience/retention than intended
      - **Severity: Medium** — not a direct boundary crossing but a systemic data-handling gap that turns any log access into a data breach.
      - **Mitigation**: Log scrubbing/redaction middleware that strips card tokens and full `customer_id` before write (log a truncated/hashed reference instead); restrict log storage access via IAM; short retention + encryption at rest for logs.
  - **2.4 Exfiltrate via the payment processor leg (B3) [OR]**
    - 2.4.1 Compromise or spoof the charge service's outbound credentials to the payment processor (API key/secret used for B3) to pull historical transaction data directly from the processor's dashboard/API
      - **Severity: High** — crosses B3; processor-side credentials often grant broad read access to full PAN/settlement data, a bigger blast radius than the tokenized data in Postgres.
      - **Mitigation**: Store processor credentials in a secrets manager with rotation; scope the processor API key to charge-create/read-own-transactions only if the processor supports scoped keys; alert on processor-side API usage from unrecognized IPs.

---

## Root Goal 3: Steal / Replay API Keys

Attacker's objective here is the credential itself — needed as a precondition for Goal 1 and parts of Goal 2.

- **3. Steal/Replay API Keys [OR]**
  - **3.1 Extract key from client-side exposure [OR]**
    - 3.1.1 Key embedded in a mobile app / SPA / public repo and extracted via reverse engineering or `git log`/public commit history
      - **Severity: High** — crosses B1; a single leaked key gives an attacker standing to hit `/api/charge` as a trusted caller indefinitely (static key, no expiry implied by current design).
      - **Mitigation**: Never ship long-lived API keys in client-distributed artifacts; use short-lived, per-session tokens minted server-side after a proper auth flow (e.g., OAuth client-credentials with short TTL) instead of a static header key for any client-facing use; add repo secret-scanning (e.g., gitleaks/trufflehog in CI) to catch committed keys pre-merge.
    - 3.1.2 Key captured via browser devtools/network tab or a malicious browser extension on a legitimate customer's machine
      - **Severity: Medium** — crosses B1, but requires attacker to already have some access to the victim's endpoint, narrowing scope vs. a fully remote leak.
      - **Mitigation**: Bind keys/tokens to originating IP or device fingerprint where feasible; short TTL + refresh flow so a captured token has limited value.
  - **3.2 Brute-force or guess a valid API key [OR]**
    - 3.2.1 Online brute force against the gateway's key-validation path (no lockout/backoff)
      - **Severity: Medium** — crosses B1; feasibility depends entirely on key entropy/length, which is unknown from the spec, so treat as plausible until proven otherwise.
      - **Mitigation**: Require high-entropy keys (>=128 bits random, not sequential/derived); enforce exponential backoff + eventual lockout/CAPTCHA-equivalent (e.g., IP ban) after N failed key attempts within a window at the gateway.
    - 3.2.2 Timing side-channel on the key-comparison logic (non-constant-time string compare against the DB-stored key/hash) to incrementally infer a valid key
      - **Severity: Low** — theoretically crosses B1 but requires very high request volume and low network jitter to exploit reliably; low practical likelihood but worth closing cheaply.
      - **Mitigation**: Use constant-time comparison (e.g., `crypto.timingSafeEqual` or equivalent) when checking the presented key against the stored hash; store keys hashed (e.g., HMAC-SHA256) rather than in plaintext in the DB so a DB leak doesn't equal key leak.
  - **3.3 Steal key via DB compromise (reuses Goal 2.1 access to read the API-key table itself) [AND]**
    - 3.3.1 Combine SQLi or DB-credential leak (2.1.1/2.1.2) with the fact that keys are "validated against the DB" — if stored in plaintext or with reversible encryption, a DB read yields every customer's key at once
      - **Severity: Critical** — crosses B4; a single DB compromise becomes total credential compromise across all customers, not just one.
      - **Mitigation**: Store only a salted hash of each API key server-side (never the raw key, never reversibly encrypted); validation compares hash(presented key) to stored hash. This makes 2.1.1/2.1.2 leak useless for key theft even if the DB is read.
  - **3.4 Social-engineer or phish an internal operator/support engineer for a customer's key or a master/admin key**
    - **Severity: Medium** — bypasses all technical boundaries via the human layer; likelihood depends on org size/process, kept at Medium absent more context.
    - **Mitigation**: No support workflow should ever require reading back a full API key (support tooling shows only last-4 + creation date, like card PAN masking); require re-authentication + audit log entry for any manual key regeneration performed by staff.

---

## Root Goal 4: Disrupt Payment Processing (DoS)

Attacker degrades or halts the ability of legitimate customers to complete charges.

- **4. Disrupt Payment Processing (DoS) [OR]**
  - **4.1 Volumetric/flood attack against the public gateway (B1) [OR]**
    - 4.1.1 Simple request flood against `POST /api/charge` or any public endpoint, exhausting gateway compute/connections
      - **Severity: High** — crosses B1; the most exposed, most reachable surface — no auth required to attempt the flood even if individual requests get rejected for bad keys.
      - **Mitigation**: Layer 3/4 DDoS protection in front of the gateway (e.g., cloud provider shield/WAF); per-IP and global rate limiting with request queuing/shedding before requests reach the charge service.
    - 4.1.2 Expensive-request amplification: submit requests engineered to be maximally expensive to validate (e.g., huge payloads, deeply nested JSON) to burn CPU per request and multiply flood impact
      - **Severity: Medium** — crosses B1; a refinement of 4.1.1 that lowers the attacker's cost-to-impact ratio.
      - **Mitigation**: Enforce request body size limits and JSON depth/complexity limits at the gateway before any parsing/validation logic runs.
  - **4.2 Resource exhaustion at the charge service or DB (B2/B4) [OR]**
    - 4.2.1 Valid-looking but high-volume charge requests (using one or many legitimate/leaked keys) that each trigger a synchronous, slow downstream call to the payment processor, exhausting charge-service worker/connection pool
      - **Severity: High** — crosses B2 and indirectly B3; ties up the internal service's limited resources (connection pool, threads) even though each individual request "looks legitimate."
      - **Mitigation**: Per-key concurrency caps and circuit breaker on the charge-service-to-processor call (fail fast + queue/backoff instead of holding connections open indefinitely); async processing with a bounded queue rather than a synchronous hold-the-thread pattern.
    - 4.2.2 DB connection pool exhaustion via high request volume with expensive/unindexed queries (e.g., charge-history lookups without proper indexing on `customer_id`)
      - **Severity: Medium** — crosses B4; a systemic performance gap that an attacker can trigger deliberately by targeting the most expensive query path.
      - **Mitigation**: Index `customer_id`/`charge_id` lookup columns; bound connection pool with queuing and timeouts; move heavy read/reporting queries off the primary transactional DB path (read replica) so charge-creation isn't starved by lookup load.
  - **4.3 Disrupt via the third-party processor relationship (B3) [OR]**
    - 4.3.1 Deliberately trigger the processor's own fraud/rate-limit controls against the charge service's shared processor account (e.g., flood with declined-card test charges) causing the processor to throttle or suspend the merchant account, halting all legitimate charges
      - **Severity: High** — crosses B3; attacker doesn't need to breach anything internal, just needs the ability to submit charge attempts (even a low-privilege/leaked key, or in a worst case an unauthenticated endpoint) that reach the processor.
      - **Mitigation**: Pre-validate cards/requests as much as possible before forwarding to the processor to avoid burning the merchant's fraud-score budget on obviously-bad input; monitor processor-reported decline rate and alert/throttle proactively before the processor imposes its own suspension; maintain a secondary processor relationship for failover.

---

## Root Goal 5: Achieve RCE / Lateral Movement into Internal Charge Service

Attacker's objective is to get code execution or a foothold on the internal, normally-unreachable charge service, using the gateway as the pivot.

- **5. RCE / Lateral Movement into Charge Service [OR]**
  - **5.1 Exploit the gateway itself to pivot into the internal segment [OR]**
    - 5.1.1 Unpatched/vulnerable gateway software (known CVE in the reverse proxy/API gateway framework) exploited for RCE on the gateway host, then pivot to the charge service over B2
      - **Severity: Critical** — crosses B1 then B2; full compromise of the boundary meant to separate untrusted internet from internal-only components.
      - **Mitigation**: Automated dependency/image scanning (e.g., Trivy/Snyk) in CI + patch SLA for the gateway's runtime and libraries; run the gateway as a minimally-privileged, non-root container/user so even a code-exec bug has limited host impact; network segmentation so the gateway host itself cannot reach Postgres directly (only the charge service can), limiting pivot value.
    - 5.1.2 Server-Side Request Forgery (SSRF) in the gateway (e.g., a webhook-URL or callback-URL field it fetches) used to reach internal-only services including the charge service or Postgres, bypassing B2's intended network isolation
      - **Severity: Critical** — crosses B2 directly by abusing the gateway's own network position rather than exploiting the charge service.
      - **Mitigation**: Allowlist outbound destinations for any gateway-initiated HTTP calls; block requests to RFC1918/link-local ranges from application code (not just firewall — defense in depth); if no such outbound-fetch feature exists today, treat this as a hardening requirement for any future feature that accepts a URL.
  - **5.2 Exploit deserialization or injection in the charge service's request handling (reached via a valid or spoofed B2 call) [OR]**
    - 5.2.1 Insecure deserialization of the charge request body (if using a serialization format/library with known unsafe-deserialization gadgets) leading to RCE on the charge service host
      - **Severity: Critical** — crosses B2; direct code execution on the internal-only component holding card tokens and DB credentials.
      - **Mitigation**: Use a safe, schema-validated serialization format (JSON with strict schema validation, not native object deserialization); if a framework-level deserializer is in use, keep it patched and configured to reject unexpected types (allowlist, not denylist).
    - 5.2.2 Command/template injection via a field that ends up interpolated into a shell command, log format string, or template engine on the charge service
      - **Severity: High** — crosses B2; requires a specific vulnerable code path to exist, so severity is High rather than Critical pending confirmation such a path exists.
      - **Mitigation**: No shelling out to construct payment requests (use the processor's SDK, not CLI invocation); parameterize any logging/templating so user-controlled fields are never treated as format strings.
  - **5.3 Supply-chain compromise of a dependency used by gateway or charge service**
    - **Severity: Critical** — bypasses B1/B2 entirely by shipping malicious code as part of a "trusted" deploy; blast radius includes both the DB (B4) and processor credentials (B3) since the compromised code runs with the charge service's full privileges.
    - **Mitigation**: Pin dependency versions with lockfiles; use a private package registry/proxy with vulnerability + provenance scanning (e.g., Sigstore/SLSA attestation checks) before allowing a new/updated package into the build; least-privilege runtime (charge service process should not have broader filesystem/network access than it needs, limiting even a successful supply-chain RCE's reach).
  - **5.4 Abuse legitimate internal access controls between gateway and charge service (B2) [OR]**
    - 5.4.1 Gateway-to-charge-service call has no independent authentication (trusts "it came from the internal network"); attacker who lands anywhere on that internal network segment (e.g., via an unrelated compromised internal host) can call the charge service directly, skipping the gateway's rate limiting/validation entirely
      - **Severity: High** — crosses B2; this is the "internal-only" boundary being enforced by network location alone rather than by identity, a common single point of failure.
      - **Mitigation**: Require service-to-service auth (mTLS or signed short-lived token) on B2 regardless of network position, so network access alone is insufficient to call the charge service — this also covers 1.3.2 above.

---

# Consolidated Threat List

Ordered by severity (Critical → High → Medium → Low). "Path" references the attack-tree node ID above.

| # | Threat | Attack Path / Goal | Severity | Mitigation |
|---|--------|--------------------|----------|-----------|
| 1 | SQL injection against Postgres via charge service input | 2.1.1 (B4) | Critical | Parameterized queries only; CI rule blocking raw SQL string concatenation; least-privilege DB role for charge service. |
| 2 | Leaked/exposed Postgres credentials allow direct DB connection, bypassing app entirely | 2.1.2 (B4) | Critical | Secrets manager for DB creds, rotation on exposure, network ACL restricting Postgres to charge-service subnet only. |
| 3 | API keys stored in DB in plaintext/reversible form; DB compromise = total credential compromise across all customers | 3.3.1 (B4) | Critical | Store salted hash of API key only; validate by comparing hash(presented) to stored hash. |
| 4 | RCE on gateway via known CVE/unpatched dependency, pivot into internal charge service | 5.1.1 (B1→B2) | Critical | Automated dependency/image scanning + patch SLA; non-root minimal-privilege gateway runtime; network segmentation so gateway can't reach Postgres directly. |
| 5 | SSRF in gateway used to reach internal-only charge service/Postgres, bypassing network isolation | 5.1.2 (B2) | Critical | Allowlist outbound destinations for gateway-initiated calls; block RFC1918/link-local targets in app code. |
| 6 | Insecure deserialization in charge service request handling leads to RCE | 5.2.1 (B2) | Critical | Schema-validated JSON only, no native object deserialization; keep any framework deserializer patched/allowlisted. |
| 7 | Supply-chain compromise of a gateway or charge-service dependency | 5.3 (B1/B2/B3/B4) | Critical | Lockfiles + private registry with vuln/provenance scanning; least-privilege runtime to cap blast radius. |
| 8 | Stolen/leaked static API key used to submit unauthorized charges directly | 1.1.1 / 3.1.1 (B1) | Critical/High | Scope keys to customer + IP allowlist or mTLS; per-key charge-velocity anomaly detection; idempotency keys; prefer short-lived tokens over static long-lived keys. |
| 9 | Replay of a captured legitimate charge request | 1.2.1 (B1) | High | Enforce TLS+HSTS; server-checked unique Idempotency-Key per charge; reject stale/reused request nonces. |
| 10 | MITM tampering with charge amount/customer_id in transit | 1.3.1 (B1) | High | End-to-end TLS with cert validation/pinning on client SDKs; revalidate amount server-side against prior quote where applicable. |
| 11 | Malformed/negative/overflow amount bypasses validation and reaches payment processor | 1.4.1 (B3) | High | Strict server-side schema validation (positive minor-units, allow-listed currency, max ceiling) before calling processor. |
| 12 | Forged/unauthenticated processor webhook marks unauthorized charge as succeeded | 1.5.1 (B3, reverse) | High | Verify processor webhook signature (HMAC/public key) on every inbound callback; treat callbacks as untrusted input. |
| 13 | Postgres exposed to broader network than intended via misconfiguration | 2.1.3 (B4) | High | Private subnet + security group restricted to charge-service hosts only; automated config-drift scanning. |
| 14 | IDOR: authenticated key used to read another customer's charge history/data | 2.2.1 (B1/B2) | High | Server-side authorization check that key's scope matches requested resource on every read; non-sequential IDs as defense-in-depth. |
| 15 | Plaintext traffic sniffing on B1/B2 exposes card tokens or customer_id | 2.3.1 (B1/B2) | High | TLS enforced on every hop including internal gateway-to-charge-service traffic; disable weak TLS versions/ciphers. |
| 16 | Compromised/leaked processor-side API credentials expose full historical transaction/PAN data | 2.4.1 (B3) | High | Secrets manager + rotation for processor creds; scope processor key to minimum needed operations; alert on anomalous processor API usage. |
| 17 | Static API key embedded in client-distributed code (app/SPA/public repo) | 3.1.1 (B1) | High | No long-lived keys in client artifacts; short-lived server-minted tokens; repo secret-scanning in CI. |
| 18 | Volumetric flood against public gateway/charge endpoint | 4.1.1 (B1) | High | L3/4 DDoS protection + WAF in front of gateway; per-IP/global rate limiting with request shedding. |
| 19 | High-volume legitimate-looking requests exhaust charge-service resources via slow synchronous processor calls | 4.2.1 (B2/B3) | High | Per-key concurrency caps + circuit breaker on processor calls; async processing with bounded queue. |
| 20 | Attacker forces processor to throttle/suspend the shared merchant account via abusive charge attempts | 4.3.1 (B3) | High | Pre-validate before forwarding to processor; monitor decline rate and self-throttle; maintain secondary processor for failover. |
| 21 | Command/template injection in a charge-service code path | 5.2.2 (B2) | High | No shell-out for processor calls (SDK only); parameterized logging/templating. |
| 22 | Charge service accepts calls from anywhere on the internal network with no independent auth (B2 secured by network location only) | 5.4.1 (B2) | High | Require mTLS or signed short-lived service token on B2 regardless of network position. |
| 23 | Internal (B2) request tampering if gateway-to-charge-service link is plaintext | 1.3.2 (B2) | Medium | mTLS or signed service-to-service token on B2. |
| 24 | Race condition on concurrent duplicate charge requests bypasses one-charge-per-order rule | 1.4.2 (application logic) | Medium | DB-level unique constraint on (customer_id, order_reference) + row lock, not just app-level check. |
| 25 | Bulk scraping of charge/customer data via weak rate limiting on read paths | 2.2.2 (B1) | Medium | Per-key/per-IP rate limiting with anomaly alerting on read volume vs. baseline. |
| 26 | Card token/PII leaked via plaintext application/gateway logs | 2.3.2 (systemic) | Medium | Log redaction/scrubbing middleware; IAM-restricted log storage; short retention + encryption at rest. |
| 27 | API key captured via browser devtools/malicious extension on customer's machine | 3.1.2 (B1) | Medium | Bind tokens to IP/device fingerprint where feasible; short TTL + refresh flow. |
| 28 | Online brute force of API keys against gateway (no lockout) | 3.2.1 (B1) | Medium | High-entropy keys; exponential backoff + lockout/IP ban after repeated failures. |
| 29 | Phishing/social engineering of internal staff for a customer or admin key | 3.4 (human layer) | Medium | Masked key display in support tooling (last-4 only); mandatory re-auth + audit log for manual key regen. |
| 30 | Expensive-payload amplification attack against gateway (large/deeply nested requests) | 4.1.2 (B1) | Medium | Request body size limits + JSON depth/complexity limits enforced before parsing. |
| 31 | DB connection pool exhaustion via expensive/unindexed charge-history queries | 4.2.2 (B4) | Medium | Index customer_id/charge_id; bounded connection pool with timeouts; offload reporting queries to read replica. |
| 32 | Timing side-channel on API key comparison logic | 3.2.2 (B1) | Low | Constant-time comparison against stored hash; store keys hashed, not plaintext. |

---

*Produced by attack-tree-agent per `plans/orchestrator-plan.md` dispatch. See `plans/stride-plan.md`
(sibling subagent output) for the component-by-component STRIDE analysis; `plans/decision.md`
(orchestrator) reconciles both.*
