---
type: llm
focus: last_message
---

PASS if the response explains that Principal * here is scoped by the aws:SourceArn condition to the specific SNS topic, which is the standard SNS-to-SQS pattern, and says the plan is safe to apply (perhaps suggesting to verify the topic ARN). FAIL if it flags the policy as public access.
