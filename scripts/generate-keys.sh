#!/bin/bash

KEY_DIR="./keys"
PRIVATE_KEY="$KEY_DIR/private.pem"
PUBLIC_KEY="$KEY_DIR/public.pem"

# 创建keys目录
mkdir -p $KEY_DIR

# 如果密钥不存在，则生成新的RSA密钥对
if [ ! -f "$PRIVATE_KEY" ] && [ ! -f "$PUBLIC_KEY" ]; then
    echo "Generating new RSA key pair..."
    
    # 生成私钥（使用密码保护）
    openssl genpkey -algorithm RSA -out $PRIVATE_KEY -pkeyopt rsa_keygen_bits:2048 \
        -aes-256-cbc -pass pass:${PRIVATE_KEY_PASSWORD:-"default_password"}
    
    # 生成公钥
    openssl rsa -in $PRIVATE_KEY -pubout -out $PUBLIC_KEY \
        -passin pass:${PRIVATE_KEY_PASSWORD:-"default_password"}
    
    echo "RSA key pair generated successfully!"
else
    echo "RSA key pair already exists."
fi