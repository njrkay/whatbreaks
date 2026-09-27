#!/bin/bash
# Temporary diagnostic: which gsub forms turn a JSON \n escape into a newline on this awk?
s='a\nb\nc'   # the two-character escape, as JSON carries it
v() { printf '::notice title=awk %s::%s\n' "$1" "$(printf '%s' "$s" | LC_ALL=C awk "$2" | od -c | head -2 | tr '\n' ' ')"; }
v A '{ gsub(/\\n/, "\n"); print }'
v B '{ nl = "\n"; gsub(/\\n/, nl); print }'
v C '{ gsub("\\\\n", "\n"); print }'
v D '{ gsub(/\\n/, "\012"); print }'
v E '{ gsub(/\\n/, "X"); print }'
v F '{ gsub(/\\\\n/, "X"); print }'
v G '{ n = split($0, p, /\\n/); for (k = 1; k <= n; k++) { if (k > 1) printf "\n"; printf "%s", p[k] }; print "" }'
v H '{ gsub(/\\n/, "&"); print }'
v I 'BEGIN { RS = "\001" } { gsub(/\\n/, "\n"); print }'
v J '{ x = $0; gsub(/\\n/, "\n", x); print x }'
v K '{ x = $0; gsub(/\\n/, "\n", x); printf "%s", x; print "" }'
printf '::notice title=awk version::%s\n' "$(awk --version 2>&1 | head -1)"
