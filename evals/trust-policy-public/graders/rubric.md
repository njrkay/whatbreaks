---
type: llm
focus: last_message
---

PASS if the response says the support role becomes assumable by any AWS principal (Principal AWS *) and that the GitHub OIDC role lost its sub condition so any GitHub repository could assume it, and gives fixes (name the principals; restore the token.actions.githubusercontent.com:sub condition). FAIL if either problem is missed.
