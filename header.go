package cryptoStorage

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/pingcap/tidb/br/pkg/storage"
)

type Header struct {
	Hash     []byte `json:"hash"`
	HashType string `json:"hash_type"`
	EncKey   []byte `json:"enc_key"`
	IV       []byte `json:"iv"`
	key      []byte
}

const (
	MaxHashSize   = 64 // aka: 512bit. md5: 128bit, sha256: 256bit, sha1: 160bit, sum32: 32 bit
	MaxEncKeySize = 1 << 16
	MaxIVSize     = 1 << 8
	KeySize       = 16        // aka: 128bit
	HeaderLenSize = 1 + 2 + 1 // hashSize: 1bit, encKeySize: 2bit, ivSize: 1bit
	MagicKeyV1    = "Encrypted&Hashed"
	MagicKeyV2    = "EncryptVersion-2"
	magicKeySize  = len(MagicKeyV1)
)

// 加密
func rsaEncrypt(publicData, origData []byte) ([]byte, error) {
	block, _ := pem.Decode(publicData)
	if block == nil {
		return []byte{}, fmt.Errorf("public key error")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return []byte{}, fmt.Errorf("public key error")
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), origData)
}

func NewHeader(key, encKey, iv []byte, hashType string) (*Header, error) {
	hash := NewHash(hashType)
	if hash == nil {
		return nil, fmt.Errorf("hash is nil")
	}
	if hash.Size() > MaxHashSize {
		return nil, fmt.Errorf("hash size larger than %d", MaxHashSize)
	}
	if len(encKey) > MaxEncKeySize {
		return nil, fmt.Errorf("enckey size larger than %d", MaxEncKeySize)
	}
	if len(iv) > MaxIVSize {
		return nil, fmt.Errorf("iv size larger than %d", MaxIVSize)
	}

	header := &Header{
		Hash:     nil,
		EncKey:   encKey,
		IV:       iv,
		key:      key,
		HashType: hashType,
	}
	return header, nil
}

func NewRandHeader(publicData []byte, hashType string) (*Header, error) {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("init key failed: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("init cipher IV failed: %w", err)
	}
	encKey, err := rsaEncrypt(publicData, key)
	if err != nil {
		return nil, fmt.Errorf("encrypt key failed: %w", err)
	}

	return NewHeader(key, encKey, iv, hashType)
}

// Bytes 生成Header的字节流
func (header *Header) BytesV1() []byte {
	// 初始化header，写入MagicKey
	buf := make([]byte, header.Size()+magicKeySize+HeaderLenSize)
	copy(buf, MagicKeyV1)
	var hashSize, encKeySize, ivSize uint16
	var offset = HeaderLenSize + magicKeySize
	// 写入Hash值
	if header.Hash != nil {
		hashSize = uint16(len(header.Hash))
		copy(buf[offset:], header.Hash)
	}
	offset = offset + MaxHashSize // 由于不同Hash算法产生的结果长度不同，按照MaxHashSize来填充

	if header.EncKey != nil {
		encKeySize = uint16(len(header.EncKey))
		copy(buf[offset:], header.EncKey)
	}
	offset = offset + int(encKeySize)

	if header.IV != nil {
		ivSize = uint16(len(header.IV))
		copy(buf[offset:], header.IV)
	}

	// 最后才写入各段的长度，如果获取Header里长度字段为0，说明加密未完成。
	buf[magicKeySize] = byte(hashSize)
	buf[magicKeySize+1] = byte(encKeySize)
	buf[magicKeySize+2] = byte(encKeySize >> 8)
	buf[magicKeySize+3] = byte(ivSize)
	return buf
}

func (header Header) Size() int {
	return MaxHashSize + len(header.EncKey) + len(header.IV)
}

func (header Header) String() string {
	return fmt.Sprintf("Hash: %x, HashType: %s, EncKey: %x, IV: %x", header.Hash, header.HashType, header.EncKey, header.IV)
}

func (header Header) Map() map[string]string {
	return map[string]string{
		"hash":      hex.EncodeToString(header.Hash),
		"enc_key":   hex.EncodeToString(header.EncKey),
		"iv":        hex.EncodeToString(header.IV),
		"hash_type": header.HashType,
	}
}

func ReadLastBytes(reader storage.ExternalFileReader, numBytes int64) ([]byte, error) {
	// 获取文件大小
	fileSize, err := reader.GetFileSize()
	if err != nil {
		return nil, fmt.Errorf("get file size failed: %w", err)
	}
	if fileSize < numBytes {
		return nil, fmt.Errorf("file size less than %d", numBytes)
	}
	// 计算偏移量
	offset := fileSize - numBytes
	if offset < 0 {
		offset = 0
		numBytes = fileSize
	}

	// 移动到计算出的偏移位置
	_, err = reader.Seek(offset, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("seek file failed: %w", err)
	}

	// 读取数据
	data := make([]byte, numBytes)
	_, err = reader.Read(data)
	if err != nil {
		return nil, fmt.Errorf("read file failed: %w", err)
	}

	return data, nil
}

func ParseHeaderV1(data storage.ExternalFileReader) (header *Header, err error) {
	buf := make([]byte, magicKeySize)
	_, err = data.Read(buf)
	if err != nil || string(buf) != MagicKeyV1 {
		return nil, fmt.Errorf("invalid file: read magicKey failed")
	}

	headerLen := make([]byte, HeaderLenSize)
	_, err = data.Read(headerLen)
	if err != nil {
		return nil, fmt.Errorf("read header failed: %w", err)
	}

	hashSize := headerLen[0]
	encKeySize := uint16(headerLen[1]) | uint16(headerLen[2])<<8
	ivSize := uint16(headerLen[3])
	// 如果headerSize为0，代表是未加密完成的文件，直接报错
	if hashSize == 0 {
		return nil, fmt.Errorf("获取原始文件Hash值为空，加密文件格式不正确")
	}

	buf = make([]byte, MaxHashSize+encKeySize+ivSize)
	_, err = data.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read header failed: %w", err)
	}
	header = &Header{
		Hash:   buf[:hashSize],
		EncKey: buf[MaxHashSize : MaxHashSize+encKeySize],
		IV:     buf[MaxHashSize+encKeySize:],
	}
	return
}
