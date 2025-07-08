package main

import (
	"fmt"
	"net/http"
	"os"

	"golang.org/x/net/webdav"
)

func main() {
	// 创建存储文件的目录
	os.MkdirAll("./data", os.ModePerm)

	// 文件存储路径
	root := http.Dir("./data")

	// 创建 WebDAV 处理器
	davHandler := &webdav.Handler{
		Prefix:     "/",
		FileSystem: webdav.Dir(root),
		LockSystem: webdav.NewMemLS(),
	}

	// 设置 WebDAV 路由
	http.Handle("/", davHandler)
	fmt.Println("WebDAV server running at http://localhost:8080/")

	// 启动 HTTP 服务
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
