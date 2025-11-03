#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
猫影视/TVBoxOSC AES-128-CBC 加密解密 Web应用
基于Flask的Web界面，实现与网页相同的功能
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import tempfile
from catvod_crypto import CatVodCrypto

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

crypto = CatVodCrypto()

@app.route('/')
def index():
    """主页面"""
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """加密接口"""
    try:
        data = request.get_json()
        plaintext = data.get('text', '')
        key = data.get('key', '123456')
        
        if not plaintext:
            return jsonify({'error': '请输入要加密的内容'}), 400
        
        encrypted = crypto.encrypt_advanced(plaintext, key)
        return jsonify({'result': encrypted})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """解密接口"""
    try:
        data = request.get_json()
        encrypted_text = data.get('text', '')
        is_base64 = data.get('is_base64', False)
        
        if not encrypted_text:
            return jsonify({'error': '请输入要解密的内容'}), 400
        
        decrypted = crypto.decrypt_advanced(encrypted_text, is_base64)
        
        # 验证是否为JSON
        is_valid, formatted = crypto.validate_json(decrypted)
        
        return jsonify({
            'result': decrypted,
            'is_json': is_valid,
            'formatted': formatted if is_valid else None
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    """文件上传接口"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': '请选择文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '请选择文件'}), 400
        
        # 保存上传的文件
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(temp_path)
        
        # 读取文件内容
        with open(temp_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({'content': content, 'filename': file.filename})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download', methods=['POST'])
def download_file():
    """文件下载接口"""
    try:
        data = request.get_json()
        content = data.get('content', '')
        filename = data.get('filename', 'result.txt')
        
        if not content:
            return jsonify({'error': '没有内容可下载'}), 400
        
        # 创建临时文件
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return send_file(temp_path, as_attachment=True, download_name=filename)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)