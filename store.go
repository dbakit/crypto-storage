package cryptoStorage

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"hash/crc32"
	"io"

	"github.com/pingcap/tidb/br/pkg/storage"
	"go.uber.org/zap"
)

func NewHash(hashType string) hash.Hash {
	switch hashType {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "crc32":
		return crc32.NewIEEE()
	default:
		return nil
	}
}

type CryptoStoreOption struct {
	PrivateData []byte // 只有Reader接口才需要私钥，如果只需要上传数据，可以不设置
	PublicData  []byte // 只有Writer接口才需要公钥，如果只需要下载数据，可以不设置
	Suffix      string // 文件后缀，默认是crypto
	HashType    string // 哈希类型，默认是md5
}

var DefaultCryptoStoreOption = &CryptoStoreOption{
	Suffix:   "crypto",
	HashType: "md5",
}

func NewCryptoStoreOption(privateData []byte, publicData []byte, suffix string, hashType string) (*CryptoStoreOption, error) {
	if len(privateData) == 0 && len(publicData) == 0 {
		return nil, fmt.Errorf("one of private data or public data must be set")
	}
	return &CryptoStoreOption{
		PrivateData: privateData,
		PublicData:  publicData,
		Suffix:      suffix,
		HashType:    hashType,
	}, nil
}

type CryptoStore struct {
	storage.ExternalStorage
	hashType   string
	privateKey []byte
	publicData []byte
	suffix     string
}

func NewCryptoStore(storageOption *storage.BackendOptions, path string, cryptoOption *CryptoStoreOption) (*CryptoStore, error) {

	b, err := storage.ParseBackend(path, storageOption)
	if err != nil {
		zap.L().Fatal("Failed to parse backend", zap.Error(err), zap.Any("conf", storageOption))
	}

	ctx := context.Background()
	store, err := storage.New(ctx, b, &storage.ExternalStorageOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create external storage: %w", err)
	}

	nw := &CryptoStore{
		ExternalStorage: store,
		hashType:        cryptoOption.HashType,
		publicData:      cryptoOption.PublicData,
		privateKey:      cryptoOption.PrivateData,
		suffix:          cryptoOption.Suffix,
	}

	if nw.NewHash() == nil {
		return nil, fmt.Errorf("invalid hash type: %s", cryptoOption.HashType)
	}
	return nw, nil
}

func (c *CryptoStore) NewHash() hash.Hash {
	return NewHash(c.hashType)
}

func (c *CryptoStore) FormatHeaderName(name string) string {
	return name + "." + c.suffix
}

func (c *CryptoStore) WriteFile(ctx context.Context, name string, data []byte) error {
	zap.L().Debug("write file", zap.String("name", name))
	writer, err := c.Create(ctx, name, nil)
	if err != nil {
		return fmt.Errorf("open file failed: %w", err)
	}
	defer writer.Close(ctx)

	_, err = writer.Write(ctx, data)
	if err != nil {
		return fmt.Errorf("write data failed: %w", err)
	}
	return nil
}

func (c *CryptoStore) ReadFile(ctx context.Context, name string) ([]byte, error) {
	reader, err := c.Open(ctx, name, nil)
	if err != nil {
		return nil, fmt.Errorf("open file failed: %w", err)
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func (c *CryptoStore) Open(ctx context.Context, name string, opt *storage.ReaderOption) (storage.ExternalFileReader, error) {
	dataReader, err := c.ExternalStorage.Open(ctx, name, opt)
	if err != nil {
		return nil, fmt.Errorf("open data file failed: %w", err)
	}

	var header *Header
	// 根据文件名是否存在，判断 Header 版本是 V1 还是 V2
	exists, err := c.FileExists(ctx, c.FormatHeaderName(name))
	if err != nil {
		return nil, fmt.Errorf("check header file exists failed: %w", err)
	}
	if exists {
		headerReader, err := c.ExternalStorage.Open(ctx, c.FormatHeaderName(name), nil)
		if err != nil {
			return nil, fmt.Errorf("open header file failed: %w", err)
		}
		header, err = ReadHeaderV2(headerReader)
		if err != nil {
			return nil, fmt.Errorf("read header version 2 failed: %w", err)
		}
	} else {
		header, err = ReadHeaderV1(dataReader)
		if err != nil {
			return nil, fmt.Errorf("read header version 1 failed: %w", err)
		}
	}

	reader, err := NewCryptoReader(dataReader, c.privateKey, header)
	if err != nil {
		return nil, fmt.Errorf("new reader failed: %w", err)
	}
	zap.L().Debug("read header", zap.Any("header", reader.header))

	return reader, nil
}

func (c *CryptoStore) Create(ctx context.Context, path string, option *storage.WriterOption) (storage.ExternalFileWriter, error) {
	dataWriter, err := c.ExternalStorage.Create(ctx, path, option)
	if err != nil {
		return nil, fmt.Errorf("create file failed: %w", err)
	}
	headerWriter, err := c.ExternalStorage.Create(ctx, c.FormatHeaderName(path), option)
	if err != nil {
		return nil, fmt.Errorf("create header file failed: %w", err)
	}

	writer, err := NewCryptoWriter(c.publicData, c.hashType, dataWriter, headerWriter)
	if err != nil {
		return nil, fmt.Errorf("new writer failed: %w", err)
	}
	return writer, nil
}

func (c *CryptoStore) Rename(ctx context.Context, src, dst string) error {
	err := c.ExternalStorage.Rename(ctx, src, dst)
	if err != nil {
		return fmt.Errorf("rename data file failed: %w", err)
	}

	// also rename header file name
	err = c.ExternalStorage.Rename(ctx, c.FormatHeaderName(src), c.FormatHeaderName(dst))
	if err != nil {
		return fmt.Errorf("rename header file failed: %w", err)
	}
	return nil
}

func (c *CryptoStore) Close() {
	c.ExternalStorage.Close()
}
