---
type: llm
focus: last_message
---

PASS if the response identifies that the new role's inline policy grants Action * on Resource * (full administrator access), rates it critical, and recommends scoping to the specific actions and resources the pipeline needs. FAIL if it calls the plan safe or misses the inline policy.
