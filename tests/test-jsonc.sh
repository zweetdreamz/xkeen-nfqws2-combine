#!/bin/sh
set -eu

# Unit test for strict_json_stream(): XKeen's Xray configs are JSONC, and the
# engine strips comments before handing them to jq. The function is extracted
# from apply-discord-nfqws2.sh and run on its own; nothing else is executed.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/apply-discord-nfqws2.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-jsonc.XXXXXX")"
trap 'rm -rf "$FIXTURE"' 0 HUP INT TERM

awk '
  /^strict_json_stream\(\) \{$/ { copying=1 }
  copying { print }
  copying && /^}$/ { exit }
' "$TARGET" > "$FIXTURE/strict_json_stream.sh"
[ -s "$FIXTURE/strict_json_stream.sh" ]
# shellcheck source=/dev/null
. "$FIXTURE/strict_json_stream.sh"

case_number=0
check() {
  expected="$1"
  case_number=$((case_number + 1))
  input="$FIXTURE/case-$case_number.jsonc"
  cat > "$input"
  actual="$(strict_json_stream "$input" | jq -cS .)" || {
    echo "ERROR: case $case_number is not valid JSON after stripping:" >&2
    strict_json_stream "$input" >&2
    exit 1
  }
  if [ "$actual" != "$(printf '%s' "$expected" | jq -cS .)" ]; then
    echo "ERROR: case $case_number: got $actual, expected $expected" >&2
    exit 1
  fi
}

# Whole-line and trailing line comments.
check '{"a":1,"b":2}' <<'EOF'
// leading comment
{
  "a": 1, // trailing
  "b": 2
}
EOF

# Block comments: multi-line, inline without inner "*", inline with "*".
check '{"a":1,"b":[1,2],"c":3}' <<'EOF'
/*
 * header
 */
{
  "a": /* note */ 1,
  "b": [1, /* a * b */ 2],
  "c": 3 /* closing */
}
EOF

# Comment markers inside strings are data, also after escaped quotes.
check '{"url":"http://example.org/a //b","pat":"/* not a comment */","q":"say \"//hi\""}' <<'EOF'
{
  "url": "http://example.org/a //b",
  "pat": "/* not a comment */", // real comment
  "q": "say \"//hi\""
}
EOF

# A block comment that ends mid-line keeps the JSON after it.
check '{"rules":[{"tag":"x"}]}' <<'EOF'
{
  "rules": [ /* start
    still comment */ {"tag": "x"} ]
}
EOF

echo "jsonc-tests-ok"
