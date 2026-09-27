#!/bin/bash
# Temporary diagnostic: trace json_scalar step by step on this platform's awk
eval "$(sed -n '/^json_scalar() {/,/^}/p' hooks/apply-gate.sh)"
j='{"cwd": "/t", "cmd": "a\nb\\c\"d"}'
printf '::notice title=full::%s\n' "$(json_scalar "$j" cmd | od -c | head -2 | tr '\n' ' ')"
step() { printf '::notice title=%s::%s\n' "$1" "$(printf '%s' "$j" | LC_ALL=C awk "$2" | od -c | head -2 | tr '\n' ' ')"; }
step s1 'BEGIN { RS = "\001" } NR == 1 { s = $0; i = index(s, "\"cmd\""); s = substr(s, i + 5); sub(/^[ \t\r\n]*:[ \t\r\n]*/, "", s); s = substr(s, 2); printf "%s", s; exit }'
step s2 'BEGIN { RS = "\001" } NR == 1 { s = $0; i = index(s, "\"cmd\""); s = substr(s, i + 5); sub(/^[ \t\r\n]*:[ \t\r\n]*/, "", s); s = substr(s, 2); gsub(/\\\\/, "\001", s); printf "%s", s; exit }'
step s3 'BEGIN { RS = "\001" } NR == 1 { s = $0; i = index(s, "\"cmd\""); s = substr(s, i + 5); sub(/^[ \t\r\n]*:[ \t\r\n]*/, "", s); s = substr(s, 2); gsub(/\\\\/, "\001", s); gsub(/\\"/, "\002", s); printf "%s", s; exit }'
step s4 'BEGIN { RS = "\001" } NR == 1 { s = $0; i = index(s, "\"cmd\""); s = substr(s, i + 5); sub(/^[ \t\r\n]*:[ \t\r\n]*/, "", s); s = substr(s, 2); gsub(/\\\\/, "\001", s); gsub(/\\"/, "\002", s); i = index(s, "\""); if (i > 0) s = substr(s, 1, i - 1); gsub(/\002/, "\"", s); printf "%s", s; exit }'
step s5 'BEGIN { RS = "\001" } NR == 1 { s = $0; i = index(s, "\"cmd\""); s = substr(s, i + 5); sub(/^[ \t\r\n]*:[ \t\r\n]*/, "", s); s = substr(s, 2); gsub(/\\\\/, "\001", s); gsub(/\\"/, "\002", s); i = index(s, "\""); if (i > 0) s = substr(s, 1, i - 1); gsub(/\002/, "\"", s); gsub(/\\n/, "\n", s); printf "%s", s; exit }'
step s6 'BEGIN { RS = "\001" } NR == 1 { s = $0; i = index(s, "\"cmd\""); s = substr(s, i + 5); sub(/^[ \t\r\n]*:[ \t\r\n]*/, "", s); s = substr(s, 2); gsub(/\\\\/, "\001", s); gsub(/\\"/, "\002", s); i = index(s, "\""); if (i > 0) s = substr(s, 1, i - 1); gsub(/\002/, "\"", s); gsub(/\\n/, "\n", s); gsub(/\\t/, "\t", s); gsub(/\\r/, "", s); gsub(/\\b/, " ", s); gsub(/\\f/, " ", s); gsub(/\\\//, "/", s); printf "%s", s; exit }'
step s7 'BEGIN { RS = "\001" } NR == 1 { s = "x\001y\nz"; n = split(s, parts, "\001"); for (k = 1; k <= n; k++) { if (k > 1) printf "%s", "\\"; printf "%s", parts[k] }; exit }'
step s8 'BEGIN { RS = "\001" } NR == 1 { s = "x\001y\nz"; n = split(s, parts, "\001"); printf "n=%d [%s] [%s]", n, parts[1], parts[2]; exit }'
