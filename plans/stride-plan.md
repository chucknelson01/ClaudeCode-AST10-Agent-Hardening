# STRIDE Threat Model: Ride-Booking API

Source reviewed: `context/system.md`

Note: `plans/orchestrator-plan.md` does not exist in this repository and was not used; this analysis is based solely on `context/system.md`.

## System Summary (as documented)

- Public endpoint: `POST /api/request-ride`
- Auth: API key in header, validated against DB
- Data flow: client -> API gateway -> booking service -> driver-matching service (3rd party)
- Data store: Postgres, holding pickup/dropoff coordinates, rider_id, driver_id, trip history
- Stated trust boundary: API gateway is public/internet-facing; booking service is internal-only

The system description is intentionally terse, so a significant part of this threat model consists of flagging what is *unstated* (and therefore unverifiable) alongside concrete threats implied by what *is* stated. Unstated controls should not be assumed to exist.

---

## Component 1: Public endpoint `POST /api/request-ride`

This is the ingress point where the trust boundary crossing from untrusted (client/internet) to the system first occurs.

**Spoofing**
- API key is the sole stated authentication mechanism. If the key is a static bearer credential, anyone who obtains it (via leakage, logging, client-side extraction from a mobile app, MITM on a non-TLS or misconfigured TLS channel) can fully impersonate the legitimate rider/caller — no mention of mutual TLS, signed requests, or per-request proof of possession.
- No mention of rider identity verification independent of the API key — if the API key identifies a *client application/partner* rather than an individual rider, one compromised or malicious caller could spoof ride requests on behalf of arbitrary `rider_id` values (see Elevation of Privilege below).
- No mention of anti-replay protection (nonces, timestamps) — a captured valid request could be replayed to spoof a new ride request.

**Tampering**
- No stated integrity control (e.g., request signing, TLS enforcement explicitly called out) on the request body. If TLS is not enforced/terminated correctly, pickup/dropoff coordinates or rider_id could be altered in transit.
- No stated input validation for coordinates — malformed, out-of-range, or malicious payloads (oversized strings, injection payloads intended for downstream services) reaching the gateway are a tampering/injection risk if not validated at this boundary.

**Repudiation**
- No mention of request logging, correlation IDs, or non-repudiable audit trail at the point of ingress. Without logging the API key/client identity, source IP, and request payload hash at this boundary, a rider or malicious caller could deny having made a request, and incident responders would lack forensic data for the true entry point of an attack.

**Information Disclosure**
- Error responses from a public endpoint are a classic disclosure vector — no mention of error-handling policy (e.g., avoiding verbose stack traces, DB error messages, or "API key not found" vs. "API key invalid" distinctions that enable key enumeration).
- API key transmitted in a header implies it must always travel over TLS; the description doesn't confirm TLS is enforced end-to-end, only that the flow exists.

**Denial of Service**
- Being the sole public endpoint and the entry point for the whole booking flow, `/api/request-ride` is the natural target for volumetric or application-layer DoS. No mention of rate limiting, per-API-key quotas, or request-size limits — without these, a single compromised or abusive API key could exhaust downstream booking service / driver-matching service / Postgres capacity.

**Elevation of Privilege**
- If the API key authenticates a *caller/application* but the request body supplies `rider_id` (or similar) directly, a caller could submit ride requests on behalf of any `rider_id`, effectively elevating from "authenticated caller" to "acts as any rider" — this is a critical gap unless the system binds the authenticated key to a specific rider identity and rejects mismatches.

---

## Component 2: API Gateway (public internet-facing)

The gateway is explicitly named as the trust-boundary enforcement point between the internet and the internal system.

**Spoofing**
- The gateway validates the API key "against DB" — if this validation is weak (e.g., plaintext key comparison without hashing, no timing-attack mitigation, no lockout/throttling on failed key attempts), it enables key-guessing/brute-force spoofing.
- No mention of how the gateway authenticates *itself* to the booking service. If the gateway simply forwards requests without a signed/trusted internal token, and the "internal-only" network boundary is the only protection, then any compromise of network segmentation (misconfigured firewall/security group, SSRF pivot, cloud metadata misconfig) allows an attacker to spoof the gateway directly against the booking service.

**Tampering**
- If the gateway forwards data to the booking service without adding integrity protection (e.g., signed internal request, mTLS), a compromised host/process anywhere on the internal network path could tamper with in-flight requests (e.g., swap `rider_id`, alter coordinates) since the booking service is described as trusting internal traffic implicitly (internal-only, not "authenticated internally").

**Repudiation**
- Gateway is the ideal place for centralized audit logging (who, what API key, what request, what response, at what time) since it sees every public request. No mention of logging/monitoring exists in the description — this is a gap that undermines incident investigation and non-repudiation for the whole system.

**Information Disclosure**
- The gateway is the boundary that should strip/sanitize internal error details before they reach the client. No mention of this control.
- DB-backed API key validation implies the gateway has direct or indirect Postgres access (or an auth service with DB access) — if key validation logic ever echoes back key metadata or verbose errors, that's a disclosure path from the public boundary into internal state.
- No mention of TLS termination details — if the gateway terminates TLS and forwards internal traffic in plaintext (common pattern), and "internal-only" is enforced purely by network ACLs rather than encryption, then anyone able to observe internal traffic (e.g., via a compromised adjacent internal service, cloud network misconfiguration, or insider) can read rider PII and coordinates in transit.

**Denial of Service**
- As the sole internet-facing component, the gateway is the choke point for the entire system's availability. No mention of DDoS protection, rate limiting per key/IP, connection limits, or WAF. A resource-exhaustion attack against the gateway (e.g., slowloris, large payloads, malformed headers) denies service to all riders.
- Since the gateway validates every request "against DB," an attacker flooding the gateway with requests (valid or invalid keys) could indirectly DoS the Postgres instance used for key validation, which is shared with core booking data — cascading failure risk.

**Elevation of Privilege**
- If the gateway is compromised (e.g., via a vulnerability in gateway software, dependency, or misconfiguration), and the booking service trusts *any* traffic arriving from the internal network without re-authenticating the caller, the attacker inherits full trust as "the gateway" — a single point of compromise that elevates from public-internet access to full internal-service access. This is the most significant architectural risk implied by the stated trust boundary: "internal-only" is a network-topology trust decision, not an identity/authorization decision, and the description gives no indication that the booking service independently verifies the gateway's identity or the legitimacy of forwarded requests (e.g., no mention of a service-to-service auth token, mTLS, or signed internal headers).

---

## Component 3: Booking Service (internal-only)

This service is explicitly trusted to receive traffic only from inside the internal network, which is the crux of the stated trust boundary.

**Spoofing**
- Because the booking service is "internal-only" with no stated internal authentication mechanism (e.g., service identity via mTLS, JWT, SPIFFE, or internal API keys), any actor who reaches the internal network — via a compromised gateway, a compromised sibling internal service, SSRF from another component, or a misconfigured network boundary — can spoof being the gateway and submit arbitrary booking requests directly. Network-location-based trust ("internal-only") without cryptographic service identity is inherently spoofable once network segmentation is bypassed.

**Tampering**
- The booking service presumably writes to Postgres (rider_id, driver_id, coordinates, trip history) and calls out to the third-party driver-matching service. No mention of input re-validation at this layer — if it fully trusts data forwarded by the gateway without re-checking bounds/types, a compromised or buggy gateway (or a MITM on the internal segment, if traffic is unencrypted) can tamper with data that ends up persisted or sent to the third party.
- No mention of transactional integrity/idempotency controls (e.g., idempotency keys) — network retries or malicious replay from the gateway boundary could result in duplicate/tampered bookings.

**Repudiation**
- No mention of audit logging within the booking service (e.g., who requested what booking, what was sent to the driver-matching service, what was written to the DB, and when). Since this service performs the actual state-changing action (creating a ride, matching a driver, persisting trip history), lack of internal audit trail here is a significant repudiation gap — both for disputing ride charges/incidents and for post-incident forensics.

**Information Disclosure**
- The booking service handles PII (rider_id, precise pickup/dropoff coordinates, driver_id) and passes it to a third party. No mention of data minimization when calling the driver-matching service (e.g., does it send exact coordinates and full rider identity, or a minimized/pseudonymized payload?). Over-sharing with a third party is a disclosure risk outside the system's own control boundary.
- No mention of encryption at rest or in transit for this internal hop; if internal-only is treated as inherently safe, plaintext internal traffic and lax storage practices are likely, exposing precise location and identity data to anyone who gains internal network or host access.

**Denial of Service**
- The booking service is the single downstream dependency for every request that passes the gateway; no mention of circuit breakers, timeouts, or backpressure when calling the third-party driver-matching service or Postgres. A slow or unavailable third party could exhaust booking service threads/connections, cascading into a full outage for all riders (a single misbehaving external dependency taking down the internal booking path).

**Elevation of Privilege**
- No mention of authorization checks within the booking service itself (e.g., verifying the requesting rider_id is entitled to view/modify a given trip, or that a caller can't request rides "as" another rider by manipulating parameters). If the booking service assumes the gateway has already fully authorized the specific action (not just authenticated the API key), and that assumption is wrong or the gateway is compromised, this is a privilege-escalation path: any internal caller effectively obtains "act as any rider/driver" capability with no additional check.

---

## Component 4: Third-Party Driver-Matching Service

This is an external dependency outside the operator's direct control, and the description gives essentially no detail about its integration security — a notable gap given it receives sensitive data.

**Spoofing**
- No mention of how the booking service authenticates the driver-matching service's *responses* (e.g., verifying the matched driver_id actually came from the legitimate third party and wasn't spoofed via DNS hijack, compromised API endpoint, or man-in-the-middle). If matching results are trusted without verification, an attacker who can intercept or spoof this integration could assign fraudulent/malicious "drivers" to real riders.
- Conversely, no mention of how the third party authenticates the booking service — if the API key/credential used to call the third party is weak or shared, it could be spoofed by other tenants of the third-party service or leaked credentials.

**Tampering**
- Data sent (coordinates, rider_id) and data received (driver_id/match result) cross a boundary to an entity outside this system's control. No stated integrity checks (e.g., signed responses, TLS certificate pinning) on data returned from the third party before it's persisted to Postgres and acted upon (e.g., dispatching a driver). A compromised or malicious third-party integration could tamper with match results, e.g., substituting a different driver_id.

**Repudiation**
- No mention of logging the exact request/response exchanged with the third party. If a dispute arises (wrong driver matched, safety incident, billing discrepancy), the absence of an audit record of what was sent to and received from the third party undermines the ability to reconstruct events or hold either party accountable.

**Information Disclosure**
- This is the most direct data-exfiltration-adjacent risk in the described architecture: rider PII and precise location data leave the system's trust boundary entirely and go to an external vendor. No mention of a data-processing agreement, data minimization, encryption in transit, or restrictions on what the third party retains/logs/re-uses. Even with no compromise at all, this is a standing information-disclosure exposure inherent to the integration as described.
- No mention of what happens to this data on the third-party side (retention, further sharing, subprocessors) — outside this system's control but relevant to the overall threat model and regulatory exposure (e.g., location data is often treated as sensitive/regulated PII).

**Denial of Service**
- Dependency on a third party for a core synchronous step (driver matching) in the booking flow means third-party unavailability or slowness directly threatens availability of the whole rider-facing feature, as noted under Booking Service. No mention of fallback, caching, retries with backoff, or SLAs.

**Elevation of Privilege**
- If the credentials used to call the third-party service are overly broad (e.g., a single shared API key with full account access rather than scoped, rotating credentials), compromise of that credential (via leakage from the booking service, logs, or config) could allow an attacker to query or manipulate matching data for the entire fleet, not just a single request — a privilege-escalation risk at the integration-credential level.

---

## Component 5: Postgres Data Store

Holds pickup/dropoff coordinates, rider_id, driver_id, and trip history — a concentration of sensitive, regulated-adjacent data (precise location + identity).

**Spoofing**
- No mention of how database clients (gateway for key validation, booking service for bookings) authenticate to Postgres (password strength, per-service credentials vs. shared credentials, certificate-based auth). Shared/static DB credentials embedded in multiple services increase the blast radius if any one service is compromised — an attacker could spoof as any authorized DB client.

**Tampering**
- No mention of database-level integrity controls: row-level constraints, write-access scoping (e.g., can the gateway's DB credential only read the API-key table, or does it also have write access to trip history?), or protection against SQL injection at the layers above (endpoint/gateway/booking service) that ultimately write to this store. Given the API key is "validated against DB," the query path for key lookup is a natural SQL-injection target if the endpoint doesn't strictly validate/parameterize input.
- No mention of backup integrity or protections against an attacker with write access silently altering historical trip records (relevant for billing disputes, legal/regulatory requests, safety investigations).

**Repudiation**
- No mention of database audit logging (who queried/modified which rows, when). Trip history is exactly the kind of data that should be tamper-evident and auditable (e.g., append-only history, DB audit trail) for dispute resolution, and no such control is described.

**Information Disclosure**
- This is the highest-value target in the system: precise pickup/dropoff coordinates plus rider_id/driver_id together enable de-anonymization and tracking of individuals' real-world movements — highly sensitive PII by any standard (and potentially "special category" data under some regulatory regimes given the ability to infer home/work addresses, visits to sensitive locations, etc.).
- No mention of encryption at rest, column-level encryption for coordinates, or access controls limiting which services/roles can query the full dataset vs. a minimized subset. If the gateway's key-validation credential also has read access to the rider/coordinate/trip tables (rather than being scoped only to an API-key table), that's a privilege/disclosure risk — the public-facing component would have unnecessary access to the most sensitive data.
- No mention of data retention policy for trip history — unbounded retention of precise location history increases disclosure impact if the DB is ever breached.

**Denial of Service**
- Single shared Postgres instance is implied for both API-key validation (hit on every public request) and core booking data. No mention of connection pooling limits, read replicas, or query timeouts — a spike in traffic at the public endpoint (legitimate or attack-driven) could exhaust DB connections/resources, denying service to the entire system including unrelated internal operations reading trip history.

**Elevation of Privilege**
- No mention of least-privilege database roles per service (gateway vs. booking service vs. any admin/analytics access). If a single broad database role/credential is shared across components (a common anti-pattern when not explicitly documented otherwise), compromise of the lowest-trust component (the public gateway) could grant an attacker elevated access to write/read the entire dataset, including other riders' trip history and driver assignments — directly undermining the stated internal-only trust boundary at the data layer, since the trust boundary described is network-based (gateway vs. booking service) but nothing indicates the *data layer* enforces an equivalent boundary.

---

## Cross-Cutting Observations on the Stated Trust Boundary

1. **The trust boundary is described only in network terms** ("gateway is public internet-facing; booking service is internal-only"). Nothing in the system description indicates a corresponding *identity/cryptographic* boundary (e.g., mTLS or signed tokens between gateway and booking service). This is the single most important gap: network segmentation alone is not a substitute for service-to-service authentication, and if internal network segmentation is ever bypassed (compromised adjacent service, SSRF, cloud misconfiguration, insider), the entire "internal-only" trust assumption collapses instantly with no secondary control.
2. **Authentication vs. authorization gap**: the description only states API-key *authentication* ("validated against DB"). No authorization model is described (what can a given API key/rider actually do — request rides only for themselves? view only their own trip history?). This is a recurring Elevation-of-Privilege theme across the endpoint, booking service, and data store.
3. **No logging/monitoring/audit trail is mentioned anywhere in the system description.** This produces a Repudiation gap at every single component and would materially hinder detection and investigation of any of the threats above.
4. **Third-party data sharing** (Information Disclosure) is a standing exposure independent of any attack — it's inherent in the documented data flow and worth flagging as a design-level risk requiring data minimization, not just an "attack" to defend against.
5. **Shared Postgres instance for both auth (API key validation) and core sensitive data** creates coupling between the lowest-trust request path (public endpoint auth) and the highest-value data (rider PII/location/trip history) — both for availability (DoS) and for access-control blast radius (Elevation of Privilege) reasons.

## Suggested Priority Areas (based on severity implied by the system description)

- **High**: Verify/establish cryptographic service-to-service trust between gateway and booking service (not network-location trust alone).
- **High**: Confirm authorization (not just authentication) binds requests to a specific rider_id, preventing one API key from acting as arbitrary riders.
- **High**: Confirm least-privilege DB credentials per service/component, especially that the gateway's key-validation path cannot read/write rider PII or trip history tables.
- **Medium**: Confirm rate limiting/quota controls exist at the gateway (DoS protection for both the gateway and shared Postgres instance).
- **Medium**: Confirm data minimization and integrity verification for the third-party driver-matching integration.
- **Medium**: Confirm audit logging exists at each hop (endpoint, gateway, booking service, DB, third-party call) to close the Repudiation gaps identified throughout.

---

**File(s) reviewed**: `context/system.md`

This threat model is based entirely on the single-paragraph system description provided; where a control is described as "no mention," that reflects absence from the documented system, not a confirmed absence in the real implementation — these should be treated as open questions to verify against the actual system, not confirmed vulnerabilities.
