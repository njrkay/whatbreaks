---
type: llm
focus: last_message
---

PASS if the response says cluster-admin is being bound to system:authenticated (every authenticated identity in the cluster becomes an admin), rates it critical, and recommends binding to specific groups. FAIL if it misses the binding.
