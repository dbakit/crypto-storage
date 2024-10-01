package cryptoStorage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/pingcap/tidb/br/pkg/storage"
	"go.uber.org/zap"
)

type CryptoWriter struct {
	dataWriter   storage.ExternalFileWriter
	headerWriter storage.ExternalFileWriter
	header       *Header
	buf          []byte
	stream       cipher.Stream
	hash         hash.Hash
}

// NewCryptoWriter : 创建加密写入器， 只需要公钥即可
func NewCryptoWriter(publicData []byte, hashType string, dataWriter, headerWriter storage.ExternalFileWriter) (nw *CryptoWriter, err error) {
	nw = &CryptoWriter{dataWriter: dataWriter, headerWriter: headerWriter, hash: NewHash(hashType)}
	nw.header, err = NewRandHeader(publicData, hashType)
	if err != nil {
		return nil, fmt.Errorf("create header failed: %w", err)
	}

	block, err := aes.NewCipher(nw.header.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher failed: %w", err)
	}
	nw.stream = cipher.NewCFBEncrypter(block, nw.header.IV)
	return
}

// Write :  覆盖 ExternalFileWriter 的 Write 方法
func (w *CryptoWriter) Write(ctx context.Context, p []byte) (int, error) {
	zap.L().Debug("write", zap.Int("len", len(p)))
	buf := w.buf // 使用缓存
	if n := len(p); n > len(buf) {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	w.stream.XORKeyStream(buf, p)
	_, err := w.hash.Write(p) /* 使用加密前源文件计算hash */
	if err != nil {
		return 0, fmt.Errorf("write hash failed: %w", err)
	}
	n, err := w.dataWriter.Write(ctx, buf)
	if err != nil {
		return 0, fmt.Errorf("write data failed: %w", err)
	}
	return n, nil
}

func (w *CryptoWriter) Close(ctx context.Context) error {
	err := w.WriteHeaderJson(ctx)
	if err != nil {
		return fmt.Errorf("write header failed: %w", err)
	}
	err = w.headerWriter.Close(ctx)
	if err != nil {
		return fmt.Errorf("close header writer failed: %w", err)
	}
	err = w.dataWriter.Close(ctx)
	if err != nil {
		return fmt.Errorf("close data writer failed: %w", err)
	}
	return nil
}

func (c *CryptoWriter) WriteHeaderV1(ctx context.Context) error {
	c.header.Hash = c.hash.Sum(nil)
	_, err := c.headerWriter.Write(ctx, c.header.BytesV1())
	if err != nil {
		return fmt.Errorf("write header failed: %w", err)
	}
	return nil
}

func (c *CryptoWriter) WriteHeaderJson(ctx context.Context) error {
	c.header.Hash = c.hash.Sum(nil)
	zap.L().Debug("write header", zap.Any("header", c.header))
	headerJSON, err := json.Marshal(c.header)
	if err != nil {
		return fmt.Errorf("marshal header map failed: %w", err)
	}
	_, err = c.headerWriter.Write(ctx, headerJSON)
	if err != nil {
		return fmt.Errorf("write header failed: %w", err)
	}
	return nil
}

type IoWriter struct {
	w storage.ExternalFileWriter
}

func NewIoWriter(w storage.ExternalFileWriter) *IoWriter {
	return &IoWriter{w: w}
}

func (w *IoWriter) Write(p []byte) (int, error) {
	return w.w.Write(context.Background(), p)
}
