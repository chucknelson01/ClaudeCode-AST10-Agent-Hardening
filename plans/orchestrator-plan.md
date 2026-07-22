# Orchestrator Plan

## Scope

System under review: **Payment API** (context/system.md)

- Public endpoint: `POST /api/charge`
- Auth: API key in header, validated against DB
- Data flow: client -> API gateway -> charge service -> payment processor (3rd party)
- Stores: card token (not raw PAN), customer_id, charge history in Postgres
- Trust boundaries:
  - Boundary 1: public internet -> API gateway (untrusted -> semi-trusted)
  - Boundary 2: API gateway -> charge service (semi-trusted -> internal-only)
  - Boundary 3: charge service -> payment processor (internal -> external 3rd party)
  - Boundary 4: charge service -> Postgres (internal -> data store)

## Subagents dispatched

1. **stride-agent** — component-by-component STRIDE analysis -> `plans/stride-plan.md` + threat list (severity + mitigation)
2. **attack-tree-agent** — goal-down attack tree analysis -> `plans/attack-tree-plan.md` + threat list (severity + mitigation)

## Eval criteria (for comparing subagent outputs)

- **Coverage**: Does the model address all 4 trust boundaries and all components (gateway, charge service, Postgres, 3rd-party processor, API key auth)?
- **STRIDE completeness**: Are all six categories (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege) represented at least once where applicable?
- **Actionability**: Is each threat paired with a concrete, specific mitigation (not generic advice like "use best practices")?
- **Severity grounded**: Is severity/likelihood justified by the specific data flow and trust boundary, not just asserted?
- **Novelty from the other model's blind spots**: STRIDE tends to miss multi-step/chained attacks; attack-tree tends to miss systemic categories (e.g., logging/repudiation). Decision.md should call out what each approach caught that the other didn't.

## Next steps

1. Dispatch stride-agent and attack-tree-agent in parallel.
2. Compare outputs against the criteria above.
3. Merge into `plans/decision.md`: deduplicated, prioritized threat list with clear ownership of mitigations.
