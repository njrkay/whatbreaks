---
type: llm
focus: last_message
---

PASS if the response recognises this as a routine ECS deployment (new task definition revision, service pointed at it, secret version rotated), gives an OK / safe verdict, and does not warn about downtime or data loss. FAIL if it rates the task definition replacement as a serious risk.
