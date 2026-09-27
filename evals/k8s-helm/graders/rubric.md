---
type: llm
focus: last_message
---

PASS if the response flags that the prod namespace would be deleted (which deletes everything inside it) and that the Helm release is replaced because the chart changed (downtime), and treats the config map change as minor. FAIL if the namespace deletion is not the top finding.
