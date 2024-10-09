package cryptoStorage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"

	"github.com/pingcap/tidb/br/pkg/storage"
)

// 解密
func rsaDecrypt(privateData []byte, cipherText []byte) ([]byte, error) {
	block, _ := pem.Decode(privateData)
	if block == nil {
		return nil, fmt.Errorf("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, cipherText)
}

type CryptoReader struct {
	storage.ExternalFileReader
	header *Header
	buf    []byte
	stream cipher.Stream
	hash   hash.Hash
}

func NewCryptoReader(dataReader storage.ExternalFileReader, privateData []byte, header *Header) (*CryptoReader, error) {
	r := &CryptoReader{
		ExternalFileReader: dataReader,
		header:             header,
		hash:               NewHash(header.HashType),
	}
	if r.hash == nil {
		return nil, fmt.Errorf("hash is nil")
	}

	err := r.initCipherStream(privateData)
	if err != nil {
		return nil, fmt.Errorf("init reader failed: %w", err)
	}
	return r, nil
}

func (r *CryptoReader) initCipherStream(privateData []byte) error {
	if len(r.header.EncKey) == 0 {
		return fmt.Errorf("header enc key is nil")
	}

	key, err := rsaDecrypt(privateData, r.header.EncKey)
	if err != nil {
		return fmt.Errorf("decrypt key failed: %w", err)
	}

	r.header.key = key
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new cipher failed: %w", err)
	}
	r.stream = cipher.NewCFBDecrypter(block, r.header.IV)
	return nil
}

// Read: 实现Reader接口
func (r *CryptoReader) Read(p []byte) (int, error) {
	buf := r.buf // 使用缓存
	if n := len(p); n > len(buf) {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}

	n, externalErr := r.ExternalFileReader.Read(buf)
	if externalErr != nil && externalErr != io.EOF {
		return n, externalErr
	}

	// 如果获取值不到buf的长度，只解密真实的值
	r.stream.XORKeyStream(p[:n], buf[:n])
	_, err := r.hash.Write(p[:n])
	if err != nil {
		return 0, fmt.Errorf("write hash failed: %w", err)
	}

	// 先计算最后一段加密值，再返回 EOF
	if externalErr == io.EOF {
		return n, io.EOF
	}

	return n, nil
}

func (r *CryptoReader) Close() error {
	return r.ExternalFileReader.Close()
}

func (r *CryptoReader) CheckSum() error {
	hash := r.hash.Sum(nil)
	// 计算hash结果与文件头的进行比较,不相等表示文件被篡改
	if !bytes.Equal(r.header.Hash, hash) {
		return fmt.Errorf("decrypt failed: file hash not match, header: %x, decrypted: %x", r.header.Hash, hash)
	}
	return nil
}

func (r *CryptoReader) Header() *Header {
	return r.header
}

func ReadHeaderV1(headerReader storage.ExternalFileReader) (*Header, error) {
	header, err := ParseHeaderV1(headerReader)
	if err != nil {
		return nil, fmt.Errorf("parse header failed: %w", err)
	}

	return header, nil
}

func ReadHeaderV2(headerReader storage.ExternalFileReader) (*Header, error) {
	data, err := io.ReadAll(headerReader)
	if err != nil {
		return nil, fmt.Errorf("read header failed: %w", err)
	}

	header := &Header{}
	err = json.Unmarshal(data, header)
	if err != nil {
		return nil, fmt.Errorf("parse header failed: %w", err)
	}

	return header, nil
}
