---
type: llm
focus: last_message
---

PASS if the response recognises the key policy as the standard default (account root, kms:*) that delegates to IAM, and gives an OK verdict. FAIL if it flags the key policy as a wildcard admin grant or cross-account trust.
