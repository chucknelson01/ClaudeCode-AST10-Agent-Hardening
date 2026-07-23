---
description: Run a full threat model by dispatching stride-agent and attack-tree-agent
---
Threat model the system in context/system.md. Use the Agent tool to
invoke stride-agent and attack-tree-agent, wait for both to return
their findings as messages, then write the combined output to
plans/stride-plan.md, plans/attack-tree-plan.md, and a merged,
prioritized plans/decision.md.

Never write to context/system.md under any circumstances — it is
human-owned ground truth. Present plans/decision.md as a
recommendation requiring human approval before any action is taken on it.
