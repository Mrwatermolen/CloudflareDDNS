# ddns for cloudflare

使用小米路由器，自动更新 Cloudflare DNS 记录

使用 Cloudflare Global API Key 进行认证。

config 配置

```json
{
  "MiWiFi": {
    "host": "miwifi.com",
    "username": "admin",
    "password": "password"
  },
  "cloudflare": {
    "email": "example@example.com",
    "api_key": "example",
    "zone_id": "example",
    "dns_record_id": "example",
    "ip_file": "/tmp/cloudflare-ddns-ip.txt"
  }
}
```
