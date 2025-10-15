#!/usr/bin/env python3
import os
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import glob

def load_private_key(password=None):
    """加载RSA私钥"""
    key_path = "./keys/private.pem"
    with open(key_path, "rb") as key_file:
        if password:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend()
            )
        else:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    return private_key

def sign_data(private_key, data):
    """使用RSA私钥对数据进行签名"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')

def process_json_files():
    """处理所有JSON文件并生成签名"""
    # 创建输出目录
    os.makedirs("./autograph", exist_ok=True)
    
    # 获取密码
    password = os.getenv('PRIVATE_KEY_PASSWORD', 'default_password')
    
    try:
        # 加载私钥
        private_key = load_private_key(password)
        print("Private key loaded successfully")
    except Exception as e:
        print(f"Error loading private key: {e}")
        return
    
    # 查找所有JSON文件
    json_files = glob.glob("./data/*.json")
    
    if not json_files:
        print("No JSON files found in ./data/ directory")
        return
    
    # 处理每个JSON文件
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 生成签名
            signature = sign_data(private_key, json.dumps(data, sort_keys=True))
            
            # 创建输出数据结构
            output_data = {
                "original_file": os.path.basename(json_file),
                "data": data,
                "signature": signature,
                "signature_algorithm": "RSA-PSS-SHA256",
                "timestamp": os.path.getmtime(json_file)
            }
            
            # 生成输出文件名
            base_name = os.path.splitext(os.path.basename(json_file))[0]
            output_file = f"./autograph/{base_name}_signed.json"
            
            # 写入签名后的文件
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            print(f"Successfully signed: {json_file} -> {output_file}")
            
        except Exception as e:
            print(f"Error processing {json_file}: {e}")

if __name__ == "__main__":
    process_json_files()