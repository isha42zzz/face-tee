# face_client.py
import requests
import base64
import os
import json
from csv_attestation import AttestationReportVerifier
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

SERVER_URL = "http://127.0.0.1:5123"


def encrypt_data(data, key):
    """使用AES-GCM加密数据"""
    # 生成随机IV
    iv = os.urandom(12)

    # 创建AES-GCM加密器
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 加密数据
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # 返回IV + 密文 + 认证标签
    return iv + encryptor.tag + ciphertext


def decrypt_data(encrypted_data, key):
    """使用AES-GCM解密数据"""
    # 提取IV、认证标签和密文
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]

    # 创建AES-GCM解密器
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # 解密数据
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def client_auth_check():
    url = f"{SERVER_URL}/auth_check"
    resp = requests.get(url)
    resp_json = resp.json()

    # 提取认证报告和公钥
    report_b64 = resp_json.get("report")
    pubkey_b64 = resp_json.get("public_key")

    if not report_b64 or not pubkey_b64:
        print("服务器响应缺少必要信息！")
        return None

    # 解码认证报告和公钥
    report = base64.b64decode(report_b64)
    pubkey_pem = base64.b64decode(pubkey_b64)

    # 验证认证报告签名
    with open("temp_report", "wb") as f:
        f.write(report)

    verifier = AttestationReportVerifier("temp_report")
    if not verifier.verify_signature():
        print("认证报告签名验证失败，服务器不可信！")
        os.remove("temp_report")
        return None

    # 验证公钥摘要是否与认证报告中的userdata匹配
    parsed_report = verifier.parse_attestation_report(return_dict=True)
    userdata_hex = parsed_report.get("Userdata")

    # 计算接收到的公钥的摘要
    pubkey_digest_calc = hashes.Hash(hashes.SHA256(), backend=default_backend())
    pubkey_digest_calc.update(pubkey_pem)
    calc_digest = pubkey_digest_calc.finalize().hex()

    # 检查userdata是否包含公钥摘要
    if not userdata_hex or not calc_digest in userdata_hex:
        print("认证报告中的userdata与公钥摘要不匹配，服务器不可信！")
        os.remove("temp_report")
        return None

    print("认证报告签名验证通过，公钥摘要验证通过，服务器可信。")
    os.remove("temp_report")

    # 加载公钥
    try:
        public_key = serialization.load_pem_public_key(
            pubkey_pem, backend=default_backend()
        )
        return public_key
    except Exception as e:
        print(f"加载公钥失败: {e}")
        return None


def register_face(image_path, encryption_key):
    """使用加密密钥注册人脸"""
    url = f"{SERVER_URL}/register_encrypted"

    # 读取图片数据
    with open(image_path, "rb") as f:
        image_data = f.read()

    # 加密图片数据
    encrypted_image = encrypt_data(image_data, encryption_key)
    encrypted_image_b64 = base64.b64encode(encrypted_image).decode("utf-8")

    # 发送加密的图片数据
    payload = {"encrypted_image": encrypted_image_b64}
    resp = requests.post(url, json=payload)

    resp_json = resp.json()
    print("注册结果:", resp_json)

    # 如果响应也是加密的，解密它
    if resp_json.get("status") == "success" and "encrypted_response" in resp_json:
        encrypted_response = base64.b64decode(resp_json["encrypted_response"])
        decrypted_response = decrypt_data(encrypted_response, encryption_key)
        decrypted_json = json.loads(decrypted_response.decode("utf-8"))
        print("解密后的注册结果:", decrypted_json)
        return decrypted_json

    return resp_json


def recognize_face(image_path, encryption_key):
    """使用加密密钥识别人脸"""
    url = f"{SERVER_URL}/recognize_encrypted"

    # 读取图片数据
    with open(image_path, "rb") as f:
        image_data = f.read()

    # 加密图片数据
    encrypted_image = encrypt_data(image_data, encryption_key)
    encrypted_image_b64 = base64.b64encode(encrypted_image).decode("utf-8")

    # 发送加密的图片数据
    payload = {"encrypted_image": encrypted_image_b64}
    resp = requests.post(url, json=payload)

    resp_json = resp.json()
    print("识别结果:", resp_json)

    # 如果响应也是加密的，解密它
    if resp_json.get("status") == "success" and "encrypted_response" in resp_json:
        encrypted_response = base64.b64decode(resp_json["encrypted_response"])
        decrypted_response = decrypt_data(encrypted_response, encryption_key)
        decrypted_json = json.loads(decrypted_response.decode("utf-8"))
        print("解密后的识别结果:", decrypted_json)
        return decrypted_json

    return resp_json


def secure_key_exchange(server_public_key):
    # 生成随机的数据加密密钥（在实际应用中，这可能是AES密钥）
    data_encryption_key = os.urandom(32)  # 256位密钥
    print(f"生成的数据加密密钥: {data_encryption_key.hex()}")

    # 使用服务器公钥加密数据加密密钥
    encrypted_key = server_public_key.encrypt(
        data_encryption_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 将加密后的密钥编码为base64字符串
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")

    # 发送加密后的密钥给服务器
    url = f"{SERVER_URL}/secure_key_exchange"
    resp = requests.post(url, json={"encrypted_key": encrypted_key_b64})
    resp_json = resp.json()

    if resp_json.get("status") != "success":
        print(f"密钥交换失败: {resp_json.get('message')}")
        return None

    print("服务器响应:")
    print(json.dumps(resp_json, indent=4))
    print("密钥交换成功，客户端保存了数据加密密钥")

    return data_encryption_key


if __name__ == "__main__":
    # 1. 远程认证并获取服务器公钥
    server_public_key = client_auth_check()

    if server_public_key:
        # 2. 安全密钥交换
        data_encryption_key = secure_key_exchange(server_public_key)

        if data_encryption_key:
            # 3. 使用数据加密密钥进行安全通信
            print("\n现在使用共享的数据加密密钥进行安全通信...")

            # 4. 加密注册和识别
            print("\n=== 加密人脸注册 ===")
            register_face("images/personA_reg.jpg", data_encryption_key)

            print("\n=== 加密人脸识别 ===")
            recognize_face("images/personA_rec.jpg", data_encryption_key)
        else:
            print("密钥交换失败，无法进行安全通信")
    else:
        print("服务器认证失败")
