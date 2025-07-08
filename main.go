package main

import (
	"crypto/subtle"
	"encoding/base64"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/webdav"
)

// 用户凭据
var (
	username     string
	passwordHash string
)

// 初始化用户凭据
func initCredentials() {
	username = getEnv("WEBDAV_USERNAME")

	// 从环境变量获取明文密码
	password := getEnv("WEBDAV_PASSWORD")

	// 程序启动时生成密码哈希
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to generate password hash: %v", err)
	}
	passwordHash = string(hash)

	log.Printf("认证凭据已初始化，用户名: %s", username)
}

// 获取环境变量，如果未设置则抛出 panic
func getEnv(key string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	panic("Environment variable " + key + " is not set")
}

// 验证密码
func verifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// 安全的字符串比较
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// 增强的认证中间件
func basicAuth(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 添加安全头
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// 从请求头中获取 Authorization 信息
		auth := r.Header.Get("Authorization")
		if auth == "" || !validateAuth(auth) {
			// 添加随机延迟防止时序攻击
			time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)

			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("Unauthorized access attempt from %s - User-Agent: %s",
				r.RemoteAddr, r.Header.Get("User-Agent"))
			return
		}

		// 如果验证成功，继续处理请求
		log.Printf("Authenticated user: %s from %s", username, r.RemoteAddr)
		handler.ServeHTTP(w, r)
	})
}

// 增强的认证验证
func validateAuth(auth string) bool {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	encoded := auth[len(prefix):]
	decoded, err := basicAuthDecode(encoded)
	if err != nil {
		return false
	}

	parts := strings.SplitN(decoded, ":", 2)
	if len(parts) != 2 {
		return false
	}

	// 使用安全的字符串比较和密码验证
	usernameValid := secureCompare(parts[0], username)
	passwordValid := verifyPassword(passwordHash, parts[1])

	return usernameValid && passwordValid
}

// basicAuthDecode 用于解码 Base64 编码的认证信息
func basicAuthDecode(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// 速率限制中间件
func rateLimitMiddleware(handler http.Handler) http.Handler {
	clients := make(map[string][]time.Time)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		now := time.Now()

		// 清理旧记录
		if times, exists := clients[clientIP]; exists {
			var recent []time.Time
			for _, t := range times {
				if now.Sub(t) < time.Minute {
					recent = append(recent, t)
				}
			}
			clients[clientIP] = recent
		}

		// 检查请求频率 (每分钟最多60次请求)
		if len(clients[clientIP]) >= 60 {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			log.Printf("Rate limit exceeded for %s", clientIP)
			return
		}

		clients[clientIP] = append(clients[clientIP], now)
		handler.ServeHTTP(w, r)
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using default environment variables")
	}
	log.Println("Loading environment variables...")
	// 初始化认证凭据
	initCredentials()

	// 创建存储文件的目录
	dataDir := getEnv("WEBDAV_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data" // 默认数据目录
	}
	log.Printf("Using data directory: %s", dataDir)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// 文件存储路径
	root := http.Dir(dataDir)

	// 创建 WebDAV 处理器
	davHandler := &webdav.Handler{
		Prefix:     "/",
		FileSystem: webdav.Dir(root),
		LockSystem: webdav.NewMemLS(),
	}

	// 应用中间件链
	handler := rateLimitMiddleware(basicAuth(davHandler))
	http.Handle("/", handler)

	port := getEnv("WEBDAV_PORT")

	log.Printf("WebDAV服务启动在端口 %s", port)
	log.Printf("数据目录: %s", dataDir)
	log.Printf("用户名: %s", username)
	log.Println("⚠️  请确保在生产环境中使用 HTTPS 和强密码")

	// 启动 HTTP 服务
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
