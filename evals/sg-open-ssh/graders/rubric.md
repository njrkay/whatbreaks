---
type: llm
focus: last_message
---

PASS if the response flags that the security group change opens port 22 (SSH) to 0.0.0.0/0 (the whole internet) as the top risk and recommends restricting the source (bastion, SSM, VPN, or specific CIDRs), while treating the instance type change as low risk. FAIL if it misses the SSH exposure or treats the plan as safe.
