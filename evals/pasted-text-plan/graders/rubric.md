---
type: llm
focus: last_message
---

PASS if the response says the database instance is destroyed and recreated because master_username forces replacement, that skip_final_snapshot = true means no snapshot is left behind so the data is lost, and that the user should not apply as-is (revert the change, or back up first). FAIL if it calls the plan safe or misses the replacement.
