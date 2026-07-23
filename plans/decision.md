# Threat Model Decision Summary — Ride-Booking API

> **This is a recommendation, not an action plan already taken.** It synthesizes `plans/stride-plan.md` (STRIDE, component-by-component) and `plans/attack-tree-plan.md` (goal-down attack trees) into a single prioritized list. **No remediation has been implemented.** A human owner must review, confirm or correct the assumptions below against the real implementation, and explicitly approve before any changes are made. `context/system.md` was not modified in producing this analysis and should not be modified based on it.

## Source basis

Both sub-agents worked from the same one-paragraph system description (`context/system.md`):

```
System: Ride-Booking API
* Public endpoint: POST /api/request-ride
* Auth: API key in header, validated against DB
* Data flow: client -> API gateway -> booking service -> driver-matching service (3rd party)
* Stores: pickup/dropoff coordinates, rider_id, driver_id, trip history in Postgres
* Trust boundary: gateway is public internet-facing; booking service is internal-only
```

Because the description is terse, most findings take the form "X is not stated, and if absent, Y follows." Treat unconfirmed items as **open questions to verify**, not confirmed vulnerabilities. Where both methodologies converge on the same underlying gap from different angles, that convergence is used as the primary signal for priority.

---

## Priority 1 — Critical (convergent findings, high blast radius)

### 1. "Internal-only" is a network label, not an enforced identity boundary
- **STRIDE**: Gateway EoP, Booking Service Spoofing — no mechanism described (mTLS, signed internal tokens, SPIFFE, etc.) by which the booking service verifies traffic actually came from the gateway rather than any other host that reached the internal network.
- **Attack tree**: Goal 2 node 6 (bypass gateway entirely by reaching booking service internally), Goal 4 node 3 (edge compromise -> internal pivot -> dump DB at rest).
- **Why critical**: Every other control in the system (API key check, rate limiting, input validation) is described as living at the gateway. If the booking service re-trusts anything that reaches it on the internal network, a single edge compromise or lateral-movement foothold collapses the entire trust model at once — this is the one gap that, left unverified, invalidates most other mitigations.
- **Action to verify**: Confirm whether the booking service independently authenticates/authorizes each request (not just accepts based on network origin). If it doesn't, this is the top remediation priority.

### 2. Authentication is confirmed; authorization is not
- **STRIDE**: Endpoint EoP, Booking Service EoP — API key authenticates a caller, but nothing confirms requests are bound to the specific rider_id that owns them.
- **Attack tree**: Goal 1 node 1 (IDOR on trip retrieval), Goal 2 node 4 (IDOR on ride modification/cancellation) — both described as requiring only a normal, self-issued API key with no pivoting.
- **Why critical**: This is the cheapest attack path in the entire model — a legitimate, non-malicious-looking API key plus a guessed/enumerated ID is enough to read or modify another rider's data or in-flight trip. Low attacker cost, potentially high impact (PII exposure, ride hijacking).
- **Action to verify**: Confirm every endpoint that accepts a rider_id/trip_id/driver_id derives the acting identity from the authenticated API key and rejects any mismatch with a client-supplied identifier, rather than trusting the client-supplied value.

### 3. Unvalidated input on the sole public endpoint enables SQL injection
- **STRIDE**: Endpoint Tampering, Postgres Tampering/Info Disclosure.
- **Attack tree**: Goal 1 node 3 (single-victim data leak via SQLi), Goal 4 node 2 (same flaw escalated to full trip_history table dump).
- **Why critical**: `POST /api/request-ride` is the only described ingress; if any field (coordinates, rider_id, etc.) reaches Postgres unparameterized, this single flaw scales from one rider's data to the entire dataset, and is the lowest-effort path to the highest-impact goal (Goal 4).
- **Action to verify**: Confirm parameterized queries / an ORM with no raw string interpolation are used for all fields on this endpoint's write and read paths.

---

## Priority 2 — High (safety or large-blast-radius, less certain to be exploitable)

### 4. Driver-matching (3rd party) responses are not confirmed to be authenticated or integrity-checked
- **STRIDE**: Driver-Matching Spoofing/Tampering.
- **Attack tree**: Goal 2 node 5 — described as the single most severe path in the whole model because it can result in a real rider being directed to an attacker posing as their driver (physical safety impact, not just data compromise).
- **Action to verify**: Confirm the booking service validates the authenticity/integrity of matching responses (e.g., mTLS, response signing) before binding a driver_id to a real rider's trip.

### 5. No least-privilege confirmed on Postgres credentials
- **STRIDE**: Postgres EoP — if the gateway's key-validation credential can also read/write rider PII and trip_history tables, the lowest-trust component has access to the highest-value data.
- **Attack tree**: Goal 4 nodes 1 and 3 (DB compromise and edge-to-internal pivot both terminate in a bulk dump; the size of that dump depends entirely on how broad the compromised credential's access is).
- **Action to verify**: Confirm per-service DB roles scoped to only the tables/operations each service needs (e.g., gateway's key-lookup role cannot SELECT from trip_history).

### 6. Third-party data sharing is a standing disclosure exposure, not just an attack surface
- **STRIDE**: Driver-Matching Info Disclosure — precise location + rider identity leaving the org's control boundary is a design-level exposure that exists even with zero compromise.
- **Attack tree**: Goal 1 node 5, Goal 4 node 6 — third-party compromise as a way to reach rider PII / bulk trip data without ever touching first-party systems.
- **Action to verify**: Confirm what subset of data is actually sent to the matcher (full coordinates + identity vs. minimized/pseudonymized), and whether a data-processing agreement / encryption-in-transit is in place. This is only partially within the org's technical control.

---

## Priority 3 — Medium (availability and forensic gaps; real but generally less severe than data/safety impact above)

### 7. DoS levers built into the described design itself
- **STRIDE**: Endpoint/Gateway/Booking Service DoS.
- **Attack tree**: Goal 3 nodes 3 and 4 — the DB-backed key validation on *every* request (including invalid ones) and the synchronous call-out to the third-party matcher both convert the system's own documented design into amplification points; generic request-volume rate limiting alone would not fully mitigate either.
- **Action to verify**: Confirm rate limiting exists ahead of the DB-lookup cost (e.g., cheap in-memory/edge rejection of malformed requests before DB round-trip), and that the third-party call has a timeout/circuit breaker so it cannot exhaust booking-service capacity.

### 8. No audit/logging trail described at any hop
- **STRIDE**: Repudiation gap flagged at every single component (endpoint, gateway, booking service, third party, Postgres).
- **Attack tree**: Implicit in every goal — none of the described attack paths would be detectable or forensically reconstructable without logging.
- **Action to verify**: Confirm request-level logging (caller identity, action, timestamp) exists at minimum at the gateway and booking service, and that database changes to trip_history are auditable.

### 9. No anti-replay / MITM protections confirmed
- **STRIDE**: Endpoint Spoofing.
- **Attack tree**: Goal 2 nodes 2 and 3 (MITM tampering with dropoff coordinates in transit; replay of a captured request to redirect or duplicate a ride).
- **Action to verify**: Confirm TLS is strictly enforced (no downgrade) between client and gateway, and that requests carry a nonce/timestamp or idempotency key to reject replays.

---

## Cross-cutting theme

Nearly every finding above traces back to the same root cause from two different analytical angles: **the system description states a network-topology trust boundary ("gateway public, booking service internal") but never states a corresponding identity/authorization boundary.** STRIDE surfaced this as a recurring Elevation-of-Privilege pattern across four separate components; the attack-tree analysis independently converged on the same gap as the pivot point for its two most severe goals (ride hijacking via matching-service spoofing, and full-dataset exfiltration via edge-to-internal pivot). This convergence — two independent methodologies landing on the same architectural question — is why Priority 1 items #1 and #2 are ranked above the others rather than treated as one gap among many.

## Recommended next step

Do not act on this document directly. The next step should be a human (or a human-directed follow-up session) walking through Priority 1 items #1–#3 against the actual implementation (not just the one-paragraph description) to convert "no mention" into either "confirmed present" or "confirmed missing," since several of the highest-priority items here hinge entirely on implementation details `context/system.md` does not capture.
