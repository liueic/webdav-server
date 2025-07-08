# WebDAV 服务端

本项目是一个基于 Go 语言的 WebDAV 服务端，支持基本认证、速率限制和安全头，适合个人或小型团队文件共享使用。

## 功能特性

- 支持 WebDAV 协议，兼容主流客户端
- 基于 HTTP Basic Auth 的用户名密码认证
- 密码以明文方式通过环境变量或 .env 文件配置，服务启动时自动哈希
- 速率限制（每分钟最多 60 次请求/每个 IP）
- 多项安全 HTTP 头防护
- 日志记录访问与认证信息

## 文件安全

-  **AES-GCM 加密**：使用行业标准的加密算法
-  **密钥派生**：使用 PBKDF2 从密码生成强密钥
-  **完整性保护**：GCM 模式提供认证加密
-  **随机 IV/Nonce**：每次加密使用随机的初始化向量
-  **透明加密**：文件在存储时自动加密，读取时自动解密

## 快速开始

### 使用Docker（推荐）

```yaml
services:
  webdav:
    image: ghcr.io/liueic/webdav-server:latest
    environment:
      - WEBDAV_USERNAME=youruser
      - WEBDAV_PASSWORD=yourpass
      - WEBDAV_CRYPTO_PASSWORD=yourcryptopass
      - WEBDAV_PORT=8080
    volumes:
      - ./data:/data
    ports:
      - "8080:8080"
    restart: unless-stopped
```
注意：

`WEBDAV_USERNAME` 和 `WEBDAV_PASSWORD` 必填

`WEBDAV_DATA_DIR` 为文件存储目录，默认为 `data`，您可以选择将其映射到宿主机内

`WEBDAV_PORT` 为监听端口，默认为 8080

`WEBDAV_CRYPTO_PASSWORD` 为加密密钥，最小32位，可以使用以下方法生成：

```bash
openssl rand -hex 32
```

### 从源码构建
```bash
git clone https://github.com/liueic/webdev-server
cd webdev-server
```

安装依赖:

```
go mod tidy
```

配置环境变量：

```
cp .env.example .env
```

```
WEBDAV_USERNAME=your_username
WEBDAV_PASSWORD=your_password
WEBDAV_DATA_DIR=./data
WEBDAV_PORT=8080
WEBDAV_CRYPTO_PASSWORD=your-very-strong-encryption-password-here-at-least-32-chars
```

启动服务

```bash
go build -o webdav-server main.go
./webdav-server
```


访问服务
使用支持 WebDAV 的客户端（如 Windows 资源管理器、macOS Finder、Cyberduck、WinSCP 等）连接：

```
http://<服务器IP>:8080/
```

输入你在 .env 文件中设置的用户名和密码即可访问

## 生产环境建议

- 强烈建议使用 HTTPS，可通过 Nginx/Apache 反向代理实现
- 使用强密码，避免弱口令
- 生产环境下请妥善保护 .env 文件和环境变量
- 可结合防火墙限制访问来源 IP
- 定期备份数据目录

## 常见问题
- 启动报错 “Environment variable ... is not set”
  请检查 .env 文件或环境变量是否正确设置

- 无法访问或认证失败
  请确认用户名和密码输入无误，且客户端支持 WebDAV 协议