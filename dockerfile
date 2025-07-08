FROM alpine

# 使用官方 Go 镜像作为构建环境
FROM golang:1.24-alpine AS builder

# 安装必要的构建工具
RUN apk add --no-cache git ca-certificates tzdata

# 设置工作目录
WORKDIR /app

# 复制 go mod 文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY *.go ./

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o webdav-server .

# 使用 Alpine 作为运行时镜像
FROM alpine:latest

# 安装 ca-certificates 用于 HTTPS 请求
RUN apk --no-cache add ca-certificates tzdata

# 创建非特权用户
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/webdav-server .

# 创建数据目录并设置权限
RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app

# 切换到非特权用户
USER appuser

# 暴露端口
EXPOSE 8080

# 设置环境变量默认值
ENV WEBDAV_PORT=8080
ENV WEBDAV_DATA_DIR=/app/data

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${WEBDAV_PORT}/ || exit 1

# 运行应用
CMD ["./webdav-server"]