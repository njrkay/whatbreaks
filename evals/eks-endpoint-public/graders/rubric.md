---
type: llm
focus: last_message
---

PASS if the response says the EKS API endpoint becomes reachable from the whole internet (endpoint_public_access true with public_access_cidrs 0.0.0.0/0) and recommends restricting the CIDRs or using the private endpoint. FAIL if it misses the exposure.
