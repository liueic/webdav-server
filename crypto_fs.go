package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/webdav"
)

// CryptoFileSystem 加密文件系统
type CryptoFileSystem struct {
	baseDir string
	gcm     cipher.AEAD
}

// NewCryptoFileSystem 创建加密文件系统
func NewCryptoFileSystem(baseDir, password string) (*CryptoFileSystem, error) {
	// 使用 PBKDF2 从密码生成密钥
	salt := []byte("webdav-crypto-salt-2024") // 在生产环境中应该使用随机盐
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// 创建 AES-GCM 密码器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	return &CryptoFileSystem{
		baseDir: baseDir,
		gcm:     gcm,
	}, nil
}

// 加密数据
func (cfs *CryptoFileSystem) encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, cfs.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := cfs.gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// 解密数据
func (cfs *CryptoFileSystem) decrypt(data []byte) ([]byte, error) {
	if len(data) < cfs.gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:cfs.gcm.NonceSize()], data[cfs.gcm.NonceSize():]
	plaintext, err := cfs.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// 获取真实文件路径
func (cfs *CryptoFileSystem) realPath(name string) string {
	return filepath.Join(cfs.baseDir, name+".enc")
}

// Mkdir 创建目录 - 修正方法签名
func (cfs *CryptoFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	realPath := filepath.Join(cfs.baseDir, name)
	return os.MkdirAll(realPath, perm)
}

// OpenFile 打开文件 - 修正方法签名
func (cfs *CryptoFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	realPath := cfs.realPath(name)

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(realPath), 0755); err != nil {
		return nil, err
	}

	return &CryptoFile{
		cfs:      cfs,
		realPath: realPath,
		name:     name,
		flag:     flag,
		perm:     perm,
	}, nil
}

// RemoveAll 删除文件或目录 - 修正方法签名
func (cfs *CryptoFileSystem) RemoveAll(ctx context.Context, name string) error {
	realPath := cfs.realPath(name)

	// 如果是目录，删除整个目录
	if info, err := os.Stat(filepath.Join(cfs.baseDir, name)); err == nil && info.IsDir() {
		return os.RemoveAll(filepath.Join(cfs.baseDir, name))
	}

	// 删除加密文件
	return os.Remove(realPath)
}

// Rename 重命名文件 - 修正方法签名
func (cfs *CryptoFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	oldPath := cfs.realPath(oldName)
	newPath := cfs.realPath(newName)

	// 确保新文件的目录存在
	if err := os.MkdirAll(filepath.Dir(newPath), 0755); err != nil {
		return err
	}

	return os.Rename(oldPath, newPath)
}

// Stat 获取文件信息 - 修正方法签名
func (cfs *CryptoFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	realPath := cfs.realPath(name)

	// 检查是否是目录
	if info, err := os.Stat(filepath.Join(cfs.baseDir, name)); err == nil && info.IsDir() {
		return &CryptoFileInfo{
			name:    filepath.Base(name),
			size:    0,
			mode:    info.Mode(),
			modTime: info.ModTime(),
			isDir:   true,
		}, nil
	}

	// 检查加密文件
	info, err := os.Stat(realPath)
	if err != nil {
		return nil, err
	}

	// 读取文件内容以获取解密后的大小
	encData, err := os.ReadFile(realPath)
	if err != nil {
		return nil, err
	}

	decData, err := cfs.decrypt(encData)
	if err != nil {
		// 如果解密失败，可能是普通文件
		return &CryptoFileInfo{
			name:    filepath.Base(name),
			size:    info.Size(),
			mode:    info.Mode(),
			modTime: info.ModTime(),
			isDir:   false,
		}, nil
	}

	return &CryptoFileInfo{
		name:    filepath.Base(name),
		size:    int64(len(decData)),
		mode:    info.Mode(),
		modTime: info.ModTime(),
		isDir:   false,
	}, nil
}

// CryptoFileInfo 加密文件信息
type CryptoFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (cfi *CryptoFileInfo) Name() string       { return cfi.name }
func (cfi *CryptoFileInfo) Size() int64        { return cfi.size }
func (cfi *CryptoFileInfo) Mode() os.FileMode  { return cfi.mode }
func (cfi *CryptoFileInfo) ModTime() time.Time { return cfi.modTime }
func (cfi *CryptoFileInfo) IsDir() bool        { return cfi.isDir }
func (cfi *CryptoFileInfo) Sys() interface{}   { return nil }

// CryptoFile 加密文件
type CryptoFile struct {
	cfs      *CryptoFileSystem
	realPath string
	name     string
	flag     int
	perm     os.FileMode
	content  []byte
	pos      int64
	file     *os.File
}

func (cf *CryptoFile) Close() error {
	if cf.file != nil {
		return cf.file.Close()
	}
	return nil
}

func (cf *CryptoFile) Read(p []byte) (n int, err error) {
	if cf.content == nil {
		if err := cf.loadContent(); err != nil {
			return 0, err
		}
	}

	if cf.pos >= int64(len(cf.content)) {
		return 0, io.EOF
	}

	n = copy(p, cf.content[cf.pos:])
	cf.pos += int64(n)
	return n, nil
}

func (cf *CryptoFile) Write(p []byte) (n int, err error) {
	if cf.content == nil {
		cf.content = make([]byte, 0)
	}

	// 扩展内容大小
	newSize := cf.pos + int64(len(p))
	if newSize > int64(len(cf.content)) {
		newContent := make([]byte, newSize)
		copy(newContent, cf.content)
		cf.content = newContent
	}

	copy(cf.content[cf.pos:], p)
	cf.pos += int64(len(p))

	// 立即保存到文件
	if err := cf.saveContent(); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (cf *CryptoFile) Seek(offset int64, whence int) (int64, error) {
	if cf.content == nil {
		if err := cf.loadContent(); err != nil {
			return 0, err
		}
	}

	switch whence {
	case io.SeekStart:
		cf.pos = offset
	case io.SeekCurrent:
		cf.pos += offset
	case io.SeekEnd:
		cf.pos = int64(len(cf.content)) + offset
	}

	if cf.pos < 0 {
		cf.pos = 0
	}

	return cf.pos, nil
}

func (cf *CryptoFile) Readdir(count int) ([]os.FileInfo, error) {
	// 这是目录读取
	dirPath := filepath.Join(cf.cfs.baseDir, cf.name)
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	var infos []os.FileInfo
	for i, entry := range entries {
		if count > 0 && i >= count {
			break
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		name := info.Name()
		if filepath.Ext(name) == ".enc" {
			name = name[:len(name)-4] // 去掉 .enc 后缀
		}

		infos = append(infos, &CryptoFileInfo{
			name:    name,
			size:    info.Size(),
			mode:    info.Mode(),
			modTime: info.ModTime(),
			isDir:   info.IsDir(),
		})
	}

	return infos, nil
}

func (cf *CryptoFile) Stat() (os.FileInfo, error) {
	return cf.cfs.Stat(context.Background(), cf.name)
}

func (cf *CryptoFile) loadContent() error {
	data, err := os.ReadFile(cf.realPath)
	if os.IsNotExist(err) {
		cf.content = make([]byte, 0)
		return nil
	}
	if err != nil {
		return err
	}

	decrypted, err := cf.cfs.decrypt(data)
	if err != nil {
		return err
	}

	cf.content = decrypted
	return nil
}

func (cf *CryptoFile) saveContent() error {
	if cf.content == nil {
		return nil
	}

	encrypted, err := cf.cfs.encrypt(cf.content)
	if err != nil {
		return err
	}

	return os.WriteFile(cf.realPath, encrypted, cf.perm)
}
