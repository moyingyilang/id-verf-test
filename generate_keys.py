#!/usr/bin/env python3
# generate_keys.py
import os
import hashlib
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import base64

# 配置参数
CONFIG = {
    "whitelist_file": "whitelist.txt",
    "output_dir": "secure_files",
    "password": "YourSecurePassword123!",  # 生产环境应从安全来源获取
    "backup_servers": [
        "https://backup1.example.com/whitelist",
        "https://backup2.example.com/whitelist"
    ]
}

def generate_keys():
    """生成RSA密钥对"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_private_key(private_key, password):
    """使用对称加密保护私钥"""
    # 序列化私钥
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 生成随机盐
    salt = os.urandom(16)
    
    # 从密码派生密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # 生成随机IV
    iv = os.urandom(16)
    
    # 使用AES加密私钥
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 填充数据
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(priv_pem) + padder.finalize()
    
    encrypted_priv = encryptor.update(padded_data) + encryptor.finalize()
    
    return salt + iv + encrypted_priv

def sign_whitelist(whitelist_path, private_key):
    """使用私钥对白名单进行签名"""
    with open(whitelist_path, 'rb') as f:
        whitelist_data = f.read()
    
    # 计算白名单哈希
    signature = private_key.sign(
        whitelist_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature

def encrypt_whitelist(whitelist_path, public_key):
    """使用公钥加密白名单"""
    with open(whitelist_path, 'rb') as f:
        whitelist_data = f.read()
    
    # 使用公钥加密
    encrypted_whitelist = public_key.encrypt(
        whitelist_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_whitelist

def generate_file_hashes():
    """生成关键文件的哈希值"""
    files_to_hash = {
        "/system/bin/secure_validator": None,
        "/system/etc/init/secure_validator.rc": None
    }
    
    for file_path in files_to_hash:
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                files_to_hash[file_path] = hashlib.sha256(f.read()).hexdigest()
    
    return files_to_hash

def save_files(public_key, encrypted_priv, signature, encrypted_whitelist, file_hashes, config):
    """保存所有文件"""
    os.makedirs(config['output_dir'], exist_ok=True)
    
    # 保存公钥
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(config['output_dir'], 'public.pem'), 'wb') as f:
        f.write(pub_pem)
    
    # 保存加密私钥
    with open(os.path.join(config['output_dir'], 'enc_private.bin'), 'wb') as f:
        f.write(encrypted_priv)
    
    # 保存签名
    with open(os.path.join(config['output_dir'], 'whitelist.sig'), 'wb') as f:
        f.write(signature)
    
    # 保存加密白名单
    with open(os.path.join(config['output_dir'], 'enc_whitelist.bin'), 'wb') as f:
        f.write(encrypted_whitelist)
    
    # 保存文件哈希
    with open(os.path.join(config['output_dir'], 'file_hashes.json'), 'w') as f:
        json.dump(file_hashes, f)
    
    # 保存配置
    with open(os.path.join(config['output_dir'], 'config.json'), 'w') as f:
        json.dump({
            'backup_servers': config['backup_servers'],
            'password_salt': base64.b64encode(os.urandom(16)).decode('utf-8')
        }, f)
    
    # 生成并保存公钥哈希
    pub_hash = hashlib.sha256(pub_pem).hexdigest()
    with open(os.path.join(config['output_dir'], 'key_hash.txt'), 'w') as f:
        f.write(f"PUBKEY_HASH={pub_hash}")

def main():
    config = CONFIG
    
    # 1. 生成密钥
    private_key, public_key = generate_keys()
    
    # 2. 加密私钥
    encrypted_priv = encrypt_private_key(private_key, config['password'])
    
    # 3. 签名白名单
    signature = sign_whitelist(config['whitelist_file'], private_key)
    
    # 4. 加密白名单
    encrypted_whitelist = encrypt_whitelist(config['whitelist_file'], public_key)
    
    # 5. 生成文件哈希
    file_hashes = generate_file_hashes()
    
    # 6. 保存所有文件
    save_files(public_key, encrypted_priv, signature, encrypted_whitelist, file_hashes, config)
    
    print("验证文件生成完成！")
    print(f"文件已保存到 {config['output_dir']} 目录")
    print("请将这些文件上传到 GitHub 仓库")

if __name__ == "__main__":
    main()
