# 猫影视/TVBoxOSC AES-128-CBC 加密解密工具

这是一个Python实现的猫影视/TVBoxOSC AES-128-CBC 加密解密工具，完全兼容网页版 [CatVodTVJsonEditor](https://zhixc.github.io/CatVodTVJsonEditor/cat_ext/index.html) 的功能。

## 功能特性

- ✅ AES-128-CBC 加密解密
- ✅ 支持文件上传和下载
- ✅ Base64 编码解码
- ✅ JSON 格式验证和格式化
- ✅ 命令行工具
- ✅ Web 界面
- ✅ 完整的错误处理

## 安装

1. 安装依赖包：

```bash
pip install -r requirements.txt
```

2. 或者单独安装：

```bash
pip install Flask pycryptodome
```

## 使用方法

### 1. 命令行使用

#### 加密文本
```bash
python catvod_crypto.py encrypt "要加密的文本内容" -k "密钥"
```

#### 解密文本
```bash
python catvod_crypto.py decrypt "加密后的文本" --base64
```

#### 加密文件
```bash
python catvod_crypto.py encrypt-file input.json -o output.encrypted
```

#### 解密文件
```bash
python catvod_crypto.py decrypt-file input.encrypted -o output.json --base64
```

### 2. Web 界面使用

启动Web服务器：

```bash
python app.py
```

然后在浏览器中访问 `http://localhost:5000`

Web界面提供：
- 实时加密解密
- 文件上传下载
- JSON格式化显示
- Base64解码选项

### 3. 编程接口使用

```python
from catvod_crypto import CatVodCrypto

crypto = CatVodCrypto()

# 加密
encrypted = crypto.encrypt_advanced("要加密的内容", "密钥")

# 解密
decrypted = crypto.decrypt_advanced(encrypted)

# 验证JSON
is_valid, formatted = crypto.validate_json(decrypted)
```

## API 说明

### CatVodCrypto 类

#### 主要方法

- `encrypt_advanced(plaintext, key)` - 高级加密，自动添加密钥和IV信息
- `decrypt_advanced(encrypted_data, is_base64=False)` - 高级解密，自动提取密钥和IV
- `encrypt_aes_cbc(plaintext, key, iv)` - 基本AES-CBC加密
- `decrypt_aes_cbc(hex_text, key, iv)` - 基本AES-CBC解密
- `encrypt_file(input_file, output_file=None)` - 加密文件
- `decrypt_file(input_file, output_file=None, is_base64=False)` - 解密文件

#### 辅助方法

- `validate_json(text)` - 验证JSON格式
- `string_to_hex(text)` - 字符串转Hex
- `hex_to_string(hex_text)` - Hex转字符串

## 加密格式说明

高级加密格式：
```
[密钥Hex][加密数据Hex][IV Hex]
```

其中：
- 密钥格式：`$#密钥#$` 的Hex编码
- IV：使用时间戳
- 加密数据：AES-128-CBC加密后的Hex字符串

## 兼容性

本工具完全兼容网页版 CatVodTVJsonEditor 的加密解密算法，可以：
- 解密网页版生成的加密配置
- 生成网页版可以解密的加密配置
- 支持相同的Base64编码格式

## 示例

### 基本使用示例

```python
from catvod_crypto import CatVodCrypto

crypto = CatVodCrypto()

# 加密JSON配置
config = {
    "name": "测试配置",
    "version": "1.0.0"
}

encrypted = crypto.encrypt_advanced(json.dumps(config, ensure_ascii=False))
print(f"加密结果: {encrypted}")

# 解密
decrypted = crypto.decrypt_advanced(encrypted)
print(f"解密结果: {decrypted}")
```

### 文件操作示例

```python
# 加密文件
encrypted_file = crypto.encrypt_file('config.json', 'config.encrypted')

# 解密文件
decrypted_file = crypto.decrypt_file('config.encrypted', 'config_decrypted.json')
```

## 错误处理

工具包含完整的错误处理：
- JSON格式错误
- 加密解密失败
- 文件操作错误
- 网络请求错误（Web版）

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！