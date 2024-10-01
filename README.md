<!--
 * @Author: zhangjt zhangjt@yingmi.cn
 * @Date: 2024-10-01 15:38:28
 * @LastEditors: zhangjt zhangjt@yingmi.cn
 * @LastEditTime: 2024-10-01 18:04:39
 * @Description: 
-->

这个包是基于tidb的br/stroage包封装的， 用来加密存储的， 参考 OSS 和 S3 的密码机逻辑， 使用的是对称加密和非对称加密结合的方式来加密数据。首先是使用 RSA 非对称加密的方式来加密随机生成的密钥， 然后使用改随机密钥对称加密的方式来加密数据，并将加密后的对称加密密钥和数据一起存储。
不过当前支持了两种 Header 格式，一种是 V1 版本， 一种是 V2 版本，在 V1 版本中，是将 Header 嵌入到文件头中， 在 V2 版本中，是将 Header 单独保存在一个文件中(默认是file.crypto)。

## 使用
PS： 目录格式可以参考 TiDB 官方文档连接：
1. https://docs.pingcap.com/zh/tidb/stable/backup-and-restore-storages
2. https://docs.pingcap.com/zh/tidb/stable/external-storage-uri

```go
	// 创建存储选项
	storageOption := &storage.BackendOptions{}
	
	// 创建加密存储选项
	cryptoOption := cryptoStorage.DefaultCryptoStoreOption
	cryptoOption.PublicData = []byte("your-public-data")
	
	// 创建 CryptoStore 实例
	store, err := cryptoStorage.NewCryptoStore(storageOption, "local:///path/to/storage", cryptoOption)
	if err != nil {
		log.Fatalf("创建 CryptoStore 失败: %v", err)
	}
	defer store.Close()
```

