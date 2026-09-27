---
type: llm
focus: last_message
---

PASS if the response flags both the firewall rule allowing TCP 22 from 0.0.0.0/0 and the Cloud SQL authorized network 0.0.0.0/0 (database reachable from the internet) as critical, and recommends removing the open ranges (private IP / Cloud SQL Auth Proxy / IAP). FAIL if it misses the Cloud SQL exposure.
