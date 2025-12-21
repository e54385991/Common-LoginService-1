# 第三方应用示例 (Demo Third-Party Application)

这是一个简单的第三方应用示例，展示如何集成 Common Login Service 进行用户认证。

## 功能特性

- 使用签名回调 URL 进行安全的用户认证
- 获取用户 ID、VIP 等级、账户余额等信息
- 简单的 Cookie 会话管理
- 完整的错误处理

## 工作原理

1. 用户点击"登录"按钮
2. 跳转到 Common Login Service (如 https://user.yuelk.com)
3. 用户在登录服务完成登录
4. 登录服务生成带签名的回调 URL，将用户信息安全传递回来
5. Demo 应用验证签名并提取用户信息
6. 用户成功登录到第三方应用

## 配置

通过环境变量配置：

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `PORT` | 服务端口 | `8081` |
| `LOGIN_URL` | 登录服务地址 | `https://user.yuelk.com` |
| `CALLBACK_URL` | 回调地址 | `http://localhost:8081/callback` |
| `SIGNED_SECRET` | HMAC 签名密钥（需与登录服务配置一致） | `your-secret-key` |
| `EXPIRE_SECONDS` | 签名有效期（秒） | `300` |

## 运行

```bash
# 直接运行（使用默认配置）
go run main.go

# 或指定配置
PORT=8081 \
LOGIN_URL=https://user.yuelk.com \
CALLBACK_URL=http://localhost:8081/callback \
SIGNED_SECRET=your-shared-secret \
go run main.go
```

## 编译

```bash
# 编译 Linux 版本
CGO_ENABLED=0 GOOS=linux go build -o demo-linux-amd64 main.go

# 编译 Windows 版本
CGO_ENABLED=0 GOOS=windows go build -o demo-windows-amd64.exe main.go
```

## 签名验证

回调 URL 包含以下参数：
- `uid` - 用户 ID
- `vip_level` - VIP 等级
- `balance` - 账户余额
- `ts` - 时间戳
- `signature` - HMAC-SHA256 签名

签名计算方式：
```
data = "balance={balance}&ts={ts}&uid={uid}&vip_level={vip_level}"
signature = HMAC-SHA256(secret, data)
```

## 注意事项

1. 生产环境必须使用 HTTPS
2. `SIGNED_SECRET` 必须与登录服务配置的密钥一致
3. 建议将 `EXPIRE_SECONDS` 设置为较短的时间（如 300 秒）
4. Cookie 会话仅作演示，生产环境应使用更安全的会话管理

## 许可证

与主项目相同 - Apache 2.0
