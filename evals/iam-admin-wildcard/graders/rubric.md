---
type: llm
focus: last_message
---

PASS if the response identifies that the deploy policy gains a statement allowing Action * on Resource * (full admin) and that AdministratorAccess is attached to the CI role, rates both as critical, and recommends scoping to specific actions/resources. FAIL if either is missed or the plan is called acceptable.
