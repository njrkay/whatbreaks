---
type: regex
pattern: "verdict\\W{0,12}(BLOCK|WARN)\\b"
flags: i
match: not_contains
target: last_message
---
