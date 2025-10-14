#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSON 处理和 RSA 加密脚本
读取 JSON 文件，为每个条目添加时间戳并使用 RSA 加密
"""

import json
import os
import subprocess
import uuid
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64


class JSONProcessor:
    def __init__(self, json_file_path, public_key_path=None, git_push=False, git_repo=None):
        """
        初始化 JSON 处理器
        
        Args:
            json_file_path: JSON 文件路径
            public_key_path: RSA 公钥文件路径（可选，如果不提供则生成新密钥对）
            git_push: 是否自动推送到 Git 仓库
            git_repo: Git 仓库地址
        """
        self.json_file_path = json_file_path
        self.public_key_path = public_key_path
        self.public_key = None
        self.git_push = git_push
        self.git_repo = git_repo
        self.device_id = str(uuid.uuid4())[:8]  # 生成8位设备ID
        
    def load_or_generate_keys(self):
        """加载或生成 RSA 密钥对"""
        if self.public_key_path and os.path.exists(self.public_key_path):
            # 从文件加载公钥
            with open(self.public_key_path, 'rb') as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            print(f"✓ 已加载公钥: {self.public_key_path}")
        else:
            # 生成新的密钥对
            print("正在生成新的 RSA 密钥对...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = private_key.public_key()
            
            # 保存私钥（注意：生产环境中应妥善保管）
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open('private_key.pem', 'wb') as f:
                f.write(private_pem)
            
            # 保存公钥
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open('public_key.pem', 'wb') as f:
                f.write(public_pem)
            
            print("✓ 已生成密钥对: private_key.pem 和 public_key.pem")
    
    def encrypt_text(self, text):
        """
        使用 RSA 公钥加密文本
        
        Args:
            text: 要加密的文本
            
        Returns:
            base64 编码的加密数据
        """
        if isinstance(text, str):
            text = text.encode('utf-8')
        
        encrypted = self.public_key.encrypt(
            text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 返回 base64 编码的字符串，方便存储在 JSON 中
        return base64.b64encode(encrypted).decode('utf-8')
    
    def process_json_data(self, data):
        """
        递归处理 JSON 数据，为每个条目添加时间戳和加密
        
        Args:
            data: JSON 数据（可以是 dict, list 或其他类型）
            
        Returns:
            处理后的数据
        """
        current_time = datetime.utcnow().isoformat() + 'Z'
        
        if isinstance(data, dict):
            processed = {}
            for key, value in data.items():
                # 为每个字典添加时间戳
                if key != 'timestamp' and key != 'encrypted_data':
                    processed[key] = self.process_json_data(value)
            
            # 添加时间戳
            processed['timestamp'] = current_time
            
            # 将整个对象序列化并加密（可选，根据需求调整）
            # 这里我们加密对象的 JSON 字符串表示
            original_data = {k: v for k, v in processed.items() if k != 'encrypted_data'}
            data_str = json.dumps(original_data, ensure_ascii=False, sort_keys=True)
            print(f"json数据 {data_str}")

            # 如果数据太大，分块加密
            if len(data_str.encode('utf-8')) > 190:  # RSA 2048 位密钥最多加密 190 字节
                # 对于大数据，只加密关键字段或使用哈希
                processed['data_hash'] = self.encrypt_text(data_str[:100])
            else:
                processed['encrypted_data'] = self.encrypt_text(data_str)
            
            return processed
            
        elif isinstance(data, list):
            return [self.process_json_data(item) for item in data]
        else:
            return data
    
    def git_commit_and_push(self, file_path):
        """
        提交并推送更改到 Git 仓库
        
        Args:
            file_path: 要提交的文件路径
        """
        try:
            print(f"\n{'='*60}")
            print("开始 Git 操作")
            print(f"{'='*60}\n")
            
            # 设备ID
            print(f"设备ID: {self.device_id}")
            
            # 目标路径
            target_path = f"autograph/{self.device_id}"
            os.makedirs(target_path, exist_ok=True)
            
            # 复制文件到目标路径
            import shutil
            target_file = os.path.join(target_path, os.path.basename(file_path))
            shutil.copy2(file_path, target_file)
            print(f"✓ 已复制文件到: {target_file}")
            
            # 添加文件到 Git
            subprocess.run(['git', 'add', target_path], check=True, shell=True)
            print(f"✓ 已添加文件到 Git")
            
            # 提交更改
            commit_message = f"Auto commit encrypted data for device {self.device_id}"
            subprocess.run(['git', 'commit', '-m', commit_message], check=True, shell=True)
            print(f"✓ 已提交更改: {commit_message}")
            
            # 推送到远程仓库
            if self.git_repo:
                print(f"\n正在推送到远程仓库: {self.git_repo}")
                subprocess.run(['git', 'push', self.git_repo], check=True, shell=True)
                print("✓ 成功推送到远程仓库")
            else:
                print("\n正在推送到默认远程仓库...")
                subprocess.run(['git', 'push'], check=True, shell=True)
                print("✓ 成功推送到远程仓库")
            
            print(f"\n{'='*60}")
            print("Git 操作完成！")
            print(f"推送路径: {target_path}")
            print(f"{'='*60}\n")
            
        except subprocess.CalledProcessError as e:
            print(f"\n✗ Git 操作失败: {e}")
            print("请确保当前目录是 Git 仓库并且已配置远程仓库")
        except Exception as e:
            print(f"\n✗ 发生错误: {e}")
    
    def run(self):
        """执行完整的处理流程"""
        print(f"\n{'='*60}")
        print("开始处理 JSON 文件")
        print(f"{'='*60}\n")
        
        # 1. 加载或生成密钥
        self.load_or_generate_keys()
        
        # 2. 读取 JSON 文件
        print(f"\n正在读取文件: {self.json_file_path}")
        
        if not os.path.exists(self.json_file_path):
            print(f"⚠ 文件不存在，创建示例 JSON 文件...")
            sample_data = {
                "users": [
                    {"id": 1, "name": "张三", "email": "zhangsan@example.com"},
                    {"id": 2, "name": "李四", "email": "lisi@example.com"}
                ],
                "settings": {
                    "theme": "dark",
                    "language": "zh-CN"
                }
            }
            with open(self.json_file_path, 'w', encoding='utf-8') as f:
                json.dump(sample_data, f, ensure_ascii=False, indent=2)
            print(f"✓ 已创建示例文件")
        
        with open(self.json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"✓ 成功读取 JSON 数据")
        
        # 3. 处理数据
        print("\n正在处理数据...")
        processed_data = self.process_json_data(data)
        print("✓ 数据处理完成")
        
        # 4. 写回文件
        output_file = self.json_file_path.replace('.json', '_processed.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(processed_data, f, ensure_ascii=False, indent=2)
        
        print(f"✓ 已保存处理后的文件: {output_file}")
        
        # 同时更新原文件
        with open(self.json_file_path, 'w', encoding='utf-8') as f:
            json.dump(processed_data, f, ensure_ascii=False, indent=2)
        
        print(f"✓ 已更新原文件: {self.json_file_path}")
        
        print(f"\n{'='*60}")
        print("处理完成！")
        print(f"{'='*60}\n")
        
        # 5. 如果启用了 Git 推送，执行 Git 操作
        if self.git_push:
            self.git_commit_and_push(self.json_file_path)


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='处理 JSON 文件并添加时间戳和 RSA 加密')
    parser.add_argument('json_file', help='要处理的 JSON 文件路径')
    parser.add_argument('--public-key', help='RSA 公钥文件路径（可选）')
    parser.add_argument('--git-push', action='store_true', help='加密后自动提交并推送到 Git 仓库')
    parser.add_argument('--git-repo', help='Git 远程仓库地址（可选，默认使用当前配置的远程仓库）')
    
    args = parser.parse_args()
    
    processor = JSONProcessor(
        args.json_file, 
        args.public_key,
        git_push=args.git_push,
        git_repo=args.git_repo
    )
    processor.run()


if __name__ == '__main__':
    main()
