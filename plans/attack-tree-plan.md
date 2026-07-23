# Attack Tree Threat Model — Ride-Booking API

**Source reviewed:** `context/system.md`

Note: `plans/orchestrator-plan.md` does not exist in this repo and was ignored per instructions; analysis is based solely on system.md content:

```
System: Ride-Booking API
* Public endpoint: POST /api/request-ride
* Auth: API key in header, validated against DB
* Data flow: client -> API gateway -> booking service -> driver-matching service (3rd party)
* Stores: pickup/dropoff coordinates, rider_id, driver_id, trip history in Postgres
* Trust boundary: gateway is public internet-facing; booking service is internal-only
```

## Assumptions / Gaps Flagged (system.md does not specify these — verify before treating tree as final)

- Whether the gateway does anything beyond API-key presence/validity check (no mention of per-key authorization/object-ownership checks, rate limiting, TLS enforcement, or request signing).
- Whether the booking service parameterizes queries against Postgres, or how it authenticates/validates responses from the 3rd-party driver-matching service.
- What data is actually forwarded to the 3rd-party matcher (assumed: pickup/dropoff coordinates, rider_id, and/or driver_id, since that's the only PII in the described data model).
- Network segmentation details for "internal-only" booking service — how strictly that boundary is enforced (firewall/VPC ACL vs. convention only).
- Backup, logging, and secrets-management practices.

These assumptions are used to build **concrete** attack paths below; they are marked so they can be validated or corrected against actual implementation.

---

## Goal 1 — Obtain another rider's trip history / PII

**Root [OR]** Attacker reads trip history, pickup/dropoff coordinates, or rider_id data belonging to a rider who is not the attacker.

```
1. [OR] IDOR on trip/ride retrieval logic
   [AND] a. Attacker holds *any* valid API key (own account, free signup, or stolen — see 2)
         b. Endpoint(s) that return trip/ride data key off a client-supplied rider_id/trip_id
            rather than binding the query to the identity resolved from the API key
         c. Attacker enumerates/guesses sequential or predictable rider_id/trip_id values
   -> CROSSES TRUST BOUNDARY at gateway->booking service if the ownership check is
      assumed to already have happened at the gateway and booking service re-trusts it.

2. [OR] Steal/obtain another rider's or an admin's API key
   [OR] a. Key leaked in mobile/web client (hardcoded, in devtools, in decompiled APK)
        b. Key intercepted in transit (no TLS pinning / TLS downgrade / MITM on client<->gateway)
        c. Key found in logs, error responses, or crash reports (key echoed back on
           validation failure, or logged in booking-service/gateway access logs)
        d. Phishing/social engineering of a rider or driver
        e. Credential-stuffing / brute-force against the key-validation DB lookup if
           keys are short, low-entropy, or not rate-limited per attempt
   Once obtained -> use key to directly call POST /api/request-ride or any read endpoint
   as the victim.

3. [AND] SQL Injection via POST /api/request-ride body fields
   a. pickup/dropoff coordinates, rider_id, or other fields are concatenated into a
      Postgres query in the booking service rather than parameterized
   b. Attacker crafts payload (e.g., in a coordinate or free-text field) to break out
      of the intended query and UNION-select rows from trip_history for other rider_ids
   c. Response (or timing/blind-SQLi channel) leaks other riders' data back to attacker
   -> Single public-facing entry point (POST /api/request-ride) makes this the highest-
      leverage path since it requires no additional pivot.

4. [AND] Direct Postgres compromise, bypassing the API entirely
   a. Attacker gains network reachability to Postgres (booking-service host compromise,
      DB port exposed to internet by misconfiguration, or SSRF from a component that
      can reach the DB tier)
   b. Attacker obtains DB credentials (leaked env vars/config, weak/reused DB password,
      secrets-manager misconfiguration)
   c. Attacker runs arbitrary SELECT against trip_history/rider tables

5. [AND] Abuse of the 3rd-party driver-matching integration as a side channel
   a. Booking service forwards rider PII (pickup/dropoff, rider_id) to the 3rd party
      for matching (data leaves the trust boundary of the primary system entirely)
   b. 3rd party is compromised, has a data breach, or is itself malicious/insufficiently
      vetted
   c. Attacker obtains rider PII via the 3rd party without ever touching the
      first-party gateway, booking service, or DB
   -> This is a trust-boundary path the org may not control directly; contractual/
      technical controls (data minimization, encryption, DPA) are the only levers.
```

**Highest-risk path:** #3 (SQLi via the one public endpoint) and #1 (IDOR) — both require nothing more than a normal, self-issued API key, no pivoting, and directly target the described `POST /api/request-ride` surface.

---

## Goal 2 — Impersonate a rider or driver to hijack/redirect a ride

**Root [OR]** Attacker causes a ride to be booked, modified, or physically redirected under a false identity, or hijacks a legitimate in-progress trip.

```
1. [OR] Use a stolen/leaked API key (see Goal 1, node 2) to submit
   POST /api/request-ride or a ride-modification call as the victim rider or driver.

2. [AND] Man-in-the-middle client<->gateway
   a. TLS not strictly enforced/pinned on client, or a downgrade is possible
   b. Attacker intercepts API key and/or tampers with in-flight request body
      (rewrites dropoff coordinates) before it reaches the gateway
   -> Redirects the ride without needing durable credential theft.

3. [AND] Replay / no anti-replay controls on request-ride
   a. Attacker captures a legitimate, previously-authorized request (e.g., via network
      capture, shared Wi-Fi, or a compromised proxy)
   b. No nonce, timestamp window, or idempotency-key binding prevents resubmission
   c. Attacker replays (optionally with modified dropoff coordinates) to redirect or
      duplicate a ride using the victim's authenticated context

4. [AND] IDOR on ride-modification/cancellation endpoints
   a. An endpoint like PATCH/PUT on a ride resource accepts a ride_id/trip_id
   b. Booking service does not verify the caller's rider_id/driver_id (derived from
      the API key) actually owns that ride_id
   c. Any authenticated attacker can alter another user's live trip — change dropoff,
      cancel it, or (most severe) reassign it to an attacker-controlled driver identity

5. [AND] Spoof/tamper with the driver-matching (3rd party) response — highest-severity, safety-impacting path
   a. Attacker sits on or compromises the booking-service <-> 3rd-party network path
      (or the 3rd party itself), since this is an external dependency outside the
      "internal-only" trust boundary once traffic leaves the booking service
   b. Booking service does not mutually authenticate or cryptographically validate
      the matching response (e.g., no mTLS, no response signing/HMAC)
   c. Attacker injects a forged match, binding an attacker-controlled "driver_id" to
      a real rider's trip
   d. Real rider is picked up by / directed to an attacker posing as their driver —
      physical safety impact, not just data compromise
   -> This is the most severe realization of "impersonate a driver to hijack a ride"
      and hinges entirely on how the described client->gateway->booking->3rd-party
      flow authenticates its *last hop*, which system.md does not specify.

6. [AND] Bypass the gateway's API-key check entirely by reaching the booking service directly
   a. Attacker finds a path onto the internal network segment where booking service
      lives (cloud misconfig exposing an internal port, SSRF pivot from another
      internal service, compromised internal host)
   b. If booking service assumes all inbound traffic has already been authenticated
      by the gateway (i.e., it does not itself re-validate an API key/identity), any
      caller reaching it internally can submit/modify rides as anyone
   -> Directly exploits the stated trust boundary: "gateway is public internet-facing;
      booking service is internal-only" implies authentication logic may live only at
      the edge, making the booking service a fully-trusting internal target once reached.
```

**Highest-risk path:** #5 (matching-service spoofing) for severity (physical safety), #6 (edge-only auth bypass) for how directly it exploits the named trust boundary.

---

## Goal 3 — Cause denial of service on the booking flow

**Root [OR]** Attacker degrades or halts the ability of legitimate riders to successfully complete `POST /api/request-ride`.

```
1. [OR] Volumetric flood of the public endpoint
   a. POST /api/request-ride is public/internet-facing by design — attacker sends
      high-volume traffic (with valid, self-service-issued, or garbage API keys)
   b. If invalid keys still trigger a DB lookup before rejection, cost is paid even
      for junk requests (see node 3).

2. [AND] Algorithmic/payload-based resource exhaustion
   a. Attacker sends oversized or deeply nested JSON bodies, huge strings in
      coordinate/address fields, or malformed-but-parseable payloads
   b. Booking service (or its JSON parser/serializer) spends disproportionate CPU/
      memory per request relative to attacker cost

3. [AND] API-key validation as an amplification/exhaustion vector
   a. Every request — valid or not — triggers a synchronous Postgres lookup to
      validate the header API key (per system.md: "validated against DB")
   b. Attacker sends a high volume of requests with random/invalid keys
   c. Postgres connection pool shared between auth-lookup queries and trip-write
      queries becomes saturated, starving legitimate bookings even though the flood
      itself never contains a valid key
   -> Directly exploits the stated auth mechanism ("API key in header, validated
      against DB") as the DoS lever, rather than needing to defeat it.

4. [AND] Synchronous dependency on the 3rd-party driver-matching service
   a. Booking service calls out to the 3rd party as part of handling
      POST /api/request-ride
   b. If this call is synchronous with no timeout/circuit breaker, an attacker who
      can slow or hang responses from (or to) the matching service — or simply a
      natural 3rd-party outage/latency spike — ties up booking-service threads/
      connections
   c. Full booking-flow outage cascades from a single external dependency, even
      though the gateway and DB are healthy
   -> Directly exploits the stated data flow "booking service -> driver-matching
      service (3rd party)" as a single point of failure.

5. [AND] Concurrency/lock-contention DoS
   a. Attacker submits many concurrent requests referencing the same rider_id or
      driver_id
   b. Poorly-scoped DB transactions/row locks in Postgres cause contention/blocking,
      stalling unrelated legitimate requests that happen to hit the same connection
      pool or table hot-spots

6. [OR] Key-farming to defeat per-key rate limiting
   a. If API keys are cheaply self-service issuable, attacker provisions many keys
   b. Distributes flood traffic across keys to stay under any per-key rate limit
      while still achieving aggregate volumetric impact (feeds back into node 1/3)
```

**Highest-risk path:** #3 and #4 — both convert the system's *own described design* (DB-backed key validation on every request; synchronous call-out to an external matcher) into the DoS mechanism, meaning generic rate-limiting on request volume alone would not fully mitigate them.

---

## Goal 4 — Exfiltrate the full Postgres trip-history dataset (mass data breach)

**Root [OR]** Attacker obtains a bulk copy of the trip_history table (pickup/dropoff coordinates, rider_id, driver_id across many/all trips), not just one rider's records.

```
1. [AND] Direct database compromise and bulk dump
   a. Network path to Postgres obtained via one of:
      - Compromised booking-service host/container (lateral movement)
      - DB port/service misconfigured and reachable from outside the intended
        internal segment
      - SSRF from gateway or booking service used to reach DB-adjacent management
        interfaces
   b. Valid DB credentials obtained via:
      - Hardcoded/leaked secrets (source control, container image, .env file, logs)
      - Weak or reused DB password
      - Misconfigured secrets manager / overly broad IAM access to secret store
   c. Attacker runs bulk SELECT/pg_dump and exfiltrates over the network (or via a
      covert channel such as DNS/HTTP tunneling if egress is restricted)

2. [AND] SQL injection escalated to bulk extraction
   a. Same injectable parameter as Goal 1/node 3 (pickup/dropoff/rider_id fields
      in POST /api/request-ride insufficiently parameterized)
   b. Attacker uses UNION-based or blind/time-based SQLi to enumerate and dump the
      entire trip_history table row-by-row (automatable with standard tooling)
   c. Rate limiting/detection evasion via slow, distributed, or low-and-slow
      extraction across many API keys/IPs
   -> Same single public entry point as Goal 1, but scaled to full-table extraction
      rather than a single victim's records.

3. [AND] Chain a public-facing compromise into the internal segment, then dump at rest
   a. Attacker achieves RCE, SSRF, or a supply-chain compromise (vulnerable/malicious
      dependency) in the gateway or booking service — the only components exposed to,
      or reachable from, the public internet per the stated trust boundary
   b. Attacker pivots from that foothold into the "internal-only" network segment
      where booking service and Postgres live, exploiting the fact that internal-only
      does not necessarily mean unreachable once the edge is breached
   c. Attacker dumps Postgres data at rest (local psql, filesystem access to data
      files, or DB credentials found on the compromised host)
   -> This is the classic "trust boundary bypass": once inside the boundary, an
      attacker can act with the same trust the booking service itself has.

4. [OR] Attack backup/export artifacts instead of production DB
   a. If Postgres backups (pg_dump snapshots) exist, check for misconfigured,
      publicly-readable or weakly-access-controlled object storage
   b. Download full historical trip-history backup directly — no need to touch
      production systems, gateway, or booking service at all
   -> Not explicitly described in system.md, but a very common real-world path for
      "exfiltrate the full dataset" goals and should be verified as in/out of scope.

5. [OR] Insider or stolen internal-admin credential path
   a. Attacker compromises an employee/operator credential with access to internal
      admin tooling or direct DB query access
   b. Uses legitimate tooling to run a bulk export, which may not be logged/alerted
      on the same way an external attack would be

6. [AND] Compromise the 3rd-party driver-matching service as a bulk data source
   a. If the 3rd party receives per-trip data (pickup/dropoff, rider_id, driver_id)
      for every matching request over time, it may itself accumulate a dataset
      equivalent to a large slice of trip_history
   b. Attacker compromises the 3rd party (breach, malicious insider, weak 3rd-party
      security posture) and exfiltrates their accumulated copy
   -> Achieves the same end goal (bulk trip-history exfiltration) without ever
      touching the primary system's gateway, booking service, or Postgres instance —
      entirely outside the org's direct technical control, governed only by
      contractual/data-minimization controls.
```

**Highest-risk path:** #2 (SQLi via the single public endpoint) for attacker cost/effort ratio; #3 (edge compromise -> internal pivot -> DB at rest) for worst-case blast radius, since it directly exploits the described "gateway public / booking service internal-only" boundary as the thing standing between an internet attacker and the full dataset.

---

## Cross-Goal Observations

1. **Single public entry point concentrates risk.** `POST /api/request-ride` is the only described ingress. It appears as a viable first step in *every* goal above (IDOR, SQLi, DoS flood, replay/tamper). Any injection or authorization flaw there has outsized impact because there is no described alternate, more-restricted API surface.
2. **"API key validated against DB" is both the auth control and a potential DoS/performance lever.** Every request paying a DB-lookup cost (Goal 3, node 3) is a direct consequence of the stated design and deserves explicit verification (caching, rate limiting, or negative-result short-circuiting).
3. **The internal-only booking service is only as trustworthy as the gateway's enforcement.** Multiple paths (Goal 2 node 6, Goal 4 node 3) hinge on whether authentication/authorization is enforced *only* at the gateway edge (common anti-pattern) versus re-validated at the booking service. System.md does not state which is true — this is the single highest-value fact to confirm, as it determines whether "internal-only" is a real security boundary or just a network-topology label.
4. **The 3rd-party driver-matching service is an under-specified trust boundary.** It appears as a viable path to three of the four goals (PII leak, ride hijack via spoofed match, bulk data exfiltration) purely because system.md confirms data flows to it but says nothing about what data, what authentication is used on that hop, or what security posture the third party maintains. This is the most consequential unknown in the whole model, particularly for the ride-hijack safety scenario (Goal 2, node 5).

No files were written by the sub-agent; all findings were reported and are captured verbatim above.
