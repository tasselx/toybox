#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
猫影视/TVBoxOSC AES-128-CBC 加密解密工具
实现与 https://zhixc.github.io/CatVodTVJsonEditor/cat_ext/index.html 相同的功能
"""

import base64
import json
import os
import re
import binascii
from datetime import datetime
from typing import Optional, Tuple
import hashlib

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
except ImportError:
    print("需要安装 pycryptodome: pip install pycryptodome")
    exit(1)


class CatVodCrypto:
    """猫影视/TVBoxOSC AES-128-CBC 加密解密类"""
    
    def __init__(self):
        self.prefix_code = "$#"
        self.suffix_code = "#$"
    
    def pad_to_16_byte(self, text: str) -> bytes:
        """将字符串填充到16字节"""
        if len(text) < 16:
            text = text.ljust(16, '0')
        return text.encode('utf-8')[:16]
    
    def encrypt_aes_cbc(self, plaintext: str, key: str, iv: str) -> str:
        """AES-128-CBC 加密，返回Hex字符串"""
        key_bytes = self.pad_to_16_byte(key)
        iv_bytes = self.pad_to_16_byte(iv)
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded_text = pad(plaintext.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)
        
        return encrypted.hex()
    
    def decrypt_aes_cbc(self, hex_text: str, key: str, iv: str) -> str:
        """AES-128-CBC 解密，输入Hex字符串，返回明文"""
        key_bytes = self.pad_to_16_byte(key)
        iv_bytes = self.pad_to_16_byte(iv)
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        encrypted_bytes = bytes.fromhex(hex_text)
        decrypted = cipher.decrypt(encrypted_bytes)
        unpadded = unpad(decrypted, AES.block_size)
        
        return unpadded.decode('utf-8')
    
    def encrypt_advanced(self, plaintext: str, key: str = "123456") -> str:
        """高级加密：包含密钥和IV的完整加密"""
        # 使用当前时间戳作为IV（毫秒级，与JavaScript兼容）
        import time
        iv = str(int(time.time() * 1000))
        
        # 加密数据
        encrypted_text = self.encrypt_aes_cbc(plaintext, key, iv)
        
        # 添加密钥和IV的标记
        key_hex = self.string_to_hex(f"{self.prefix_code}{key}{self.suffix_code}")
        iv_hex = self.string_to_hex(iv)
        
        return f"{key_hex}{encrypted_text}{iv_hex}"
    
    def decrypt_advanced(self, encrypted_data: str, is_base64: bool = False) -> str:
        """高级解密：自动提取密钥和IV"""
        if is_base64:
            # 如果是Base64编码，先解码
            encrypted_data = base64.b64decode(encrypted_data.split("**")[1] if "**" in encrypted_data else encrypted_data).decode('utf-8')
        
        # 按照网页JavaScript代码的逻辑实现
        # 查找密钥标记的结束位置
        prefix_code_hex = self.string_to_hex(self.prefix_code)  # "$#" 的Hex
        suffix_code_hex = self.string_to_hex(self.suffix_code)  # "#$" 的Hex
        
        # 查找密钥结束位置
        key_end = encrypted_data.find(suffix_code_hex) + len(suffix_code_hex)
        if key_end == len(suffix_code_hex) - 1:  # 没找到
            raise ValueError("无法找到密钥标记")
        
        pwd_mix = encrypted_data[:key_end]
        remaining = encrypted_data[key_end:]
        
        # 提取密钥Hex
        pwd_in_hex = pwd_mix[len(prefix_code_hex):len(pwd_mix) - len(suffix_code_hex)]
        key = self.hex_to_string(pwd_in_hex)
        
        # 提取IV Hex（最后26位，因为毫秒级时间戳是13位数字，Hex表示是26个字符）
        # 毫秒级时间戳通常是13位数字，Hex表示是26个字符
        roundtime_in_hex = remaining[-26:]
        encrypted_text = remaining[:-26]
        
        # IV是时间戳的Hex，需要正确处理
        # 直接将Hex转换为字节，然后使用pad_to_16_byte方法
        try:
            iv_raw = bytes.fromhex(roundtime_in_hex)
            # 将字节转换为字符串
            iv_str = iv_raw.decode('utf-8', errors='ignore')
            # 使用与加密时相同的填充方法
            round_time = self.pad_to_16_byte(iv_str).decode('utf-8')
        except:
            # 如果转换失败，使用默认IV
            default_iv = str(int(datetime.now().timestamp()))
            round_time = self.pad_to_16_byte(default_iv).decode('utf-8')
        
        # 解密
        return self.decrypt_aes_cbc(encrypted_text, key, round_time)
    
    def string_to_hex(self, text: str) -> str:
        """字符串转Hex"""
        return text.encode('utf-8').hex()
    
    def hex_to_string(self, hex_text: str) -> str:
        """Hex转字符串"""
        return bytes.fromhex(hex_text).decode('utf-8')
    
    def validate_json(self, text: str) -> Tuple[bool, str]:
        """验证JSON格式"""
        try:
            parsed = json.loads(text)
            return True, json.dumps(parsed, indent=2, ensure_ascii=False)
        except json.JSONDecodeError as e:
            return False, f"JSON格式错误: {e}"
    
    def encrypt_file(self, input_file: str, output_file: Optional[str] = None) -> str:
        """加密文件"""
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        encrypted = self.encrypt_advanced(content)
        
        if output_file is None:
            output_file = f"{input_file}.encrypted"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(encrypted)
        
        return output_file
    
    def decrypt_file(self, input_file: str, output_file: Optional[str] = None, is_base64: bool = False) -> str:
        """解密文件"""
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        
        decrypted = self.decrypt_advanced(content, is_base64)
        
        if output_file is None:
            if input_file.endswith('.encrypted'):
                output_file = input_file[:-10]  # 移除 .encrypted 扩展名
            else:
                output_file = f"{input_file}.decrypted"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(decrypted)
        
        return output_file


def main():
    """主函数，提供命令行界面"""
    import argparse
    
    crypto = CatVodCrypto()
    
    parser = argparse.ArgumentParser(description='猫影视/TVBoxOSC AES-128-CBC 加密解密工具')
    parser.add_argument('action', choices=['encrypt', 'decrypt', 'encrypt-file', 'decrypt-file'], 
                       help='操作类型')
    parser.add_argument('input', help='输入内容或文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('-k', '--key', default='123456', help='加密密钥 (默认: 123456)')
    parser.add_argument('--base64', action='store_true', help='解密时使用Base64解码')
    
    args = parser.parse_args()
    
    try:
        if args.action == 'encrypt':
            result = crypto.encrypt_advanced(args.input, args.key)
            print("加密结果:")
            print(result)
            
        elif args.action == 'decrypt':
            result = crypto.decrypt_advanced(args.input, args.base64)
            is_valid, formatted = crypto.validate_json(result)
            if is_valid:
                print("解密结果 (格式化JSON):")
                print(formatted)
            else:
                print("解密结果:")
                print(result)
                print(f"警告: {formatted}")
                
        elif args.action == 'encrypt-file':
            output_file = crypto.encrypt_file(args.input, args.output)
            print(f"文件加密完成: {output_file}")
            
        elif args.action == 'decrypt-file':
            output_file = crypto.decrypt_file(args.input, args.output, args.base64)
            # 尝试格式化JSON输出
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            is_valid, formatted = crypto.validate_json(content)
            if is_valid:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(formatted)
                print(f"文件解密完成 (已格式化JSON): {output_file}")
            else:
                print(f"文件解密完成: {output_file}")
                print(f"警告: {formatted}")
    
    except Exception as e:
        print(f"错误: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())