---
type: llm
focus: last_message
---

PASS if the response says the RDS instance aws_db_instance.main will be replaced (destroyed and recreated) because master_username cannot be changed in place, warns that its data would be lost and that no final snapshot is taken, and tells the user not to apply as-is (or to take a backup / revert the change first). FAIL if it calls the plan safe, misses the replacement, or does not mention data loss.
