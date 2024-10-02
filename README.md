<!--
 * @Author: zhangjt zhangjt@yingmi.cn
 * @Date: 2024-10-01 15:38:28
 * @LastEditors: zhangjt zhangjt@yingmi.cn
 * @LastEditTime: 2024-10-01 18:04:39
 * @Description: 
-->

这个包是基于tidb的br/stroage包封装的，用来加密存储的，参考 OSS 和 S3 的密码机逻辑，使用的是对称加密和非对称加密结合的方式来加密数据。首先是使用 RSA 非对称加密的方式来加密随机生成的密钥，然后使用该随机密钥对文件做对称加密，在 Header 中会记录原始文件的 Hash 值，提供防篡改功能。    
代码里支持两种 Header 文件格式: V1 版本将 Header 嵌入到文件头中，V2 版本是将 Header 单独保存在一个文件中(默认是file.crypto，可以通过CryptoStoreOption.Suffix来自定义)。不过 V1 版本已经是废弃版本了，原因是 S3 不支持在写入文件后再修改文件内容，当前只支持生成 V2 版本的 Header 文件。下面是一个 Header 文件的示例：
```json
{"hash":"LqIvjzIHBEbjqITikWLMSA==","hash_type":"md5","enc_key":"iJr8xMsSeTya9g3xK11myqeNHIa2MuFUpjvBGqo93KluvA4SfcPaaD4+du1BsGMMpFzTzTCD4OqxiawUOZwDJA1htWgZLsmnWHwem8yQ55dhPuINjxzcLmpdmF9ZNF7CRu0AxhNDKF86AXrtb1iiTmzQzKYW+uVvK1pmo+V4eNJ+6AV1hFg8Wx+afCOYn2O52aXVEkr50as2RF1rqNC0PyWg4m8/LPxtUgSMhShV6ZBcFhU3s06JSfeBjgyuku8xlL/kdqiSldX6kMtA4laUeOJ1tDQY6joMCdyapkjKW0NveMgRVYFgf5ksknK0Lux/IXO4OI4q1wAiie1mMFh+Ww==","iv":"EDaMoUrp2j27r2KfQXFWAA=="}
```

## 使用
PS： 目录格式可以参考 TiDB 官方文档连接：
1. https://docs.pingcap.com/zh/tidb/stable/backup-and-restore-storages
2. https://docs.pingcap.com/zh/tidb/stable/external-storage-uri

```go
	// 创建存储选项
	storageOption := &storage.BackendOptions{}
	
	// 创建加密存储选项
	cryptoOption := &cryptoStorage.CryptoStoreOption{
	}
	cryptoOption.PublicData = []byte("your-public-data")
	
	// 创建 CryptoStore 实例
	store, err := cryptoStorage.NewCryptoStore(storageOption, "local:///path/to/storage", cryptoOption)
	if err != nil {
		log.Fatalf("创建 CryptoStore 失败: %v", err)
	}
	defer store.Close()
```

