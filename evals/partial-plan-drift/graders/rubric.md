---
type: llm
focus: last_message
---

PASS if the response notes that the plan is partial (built with -target) so dependent resources are not updated, mentions the drift (a security group changed outside Terraform and an instance no longer exists), and recommends a full plan afterwards. FAIL if it ignores the targeting or the drift.
