---
type: llm
focus: last_message
---

PASS if the response says the users table would be destroyed (losing its data) and recreated empty under the new address because the block was renamed without a `moved` block, and gives the exact moved block (from aws_dynamodb_table.users to aws_dynamodb_table.users_v2). FAIL if it accepts the destroy or omits the moved block.
