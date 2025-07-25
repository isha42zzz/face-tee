import requests
import base64
import os
import json
from .attestation import AttestationReportVerifier
from .crypto_utils import encrypt_aes_gcm, decrypt_aes_gcm
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from . import config

def client_auth_check(server_url: str):
    url = f"{server_url}/auth_check"
    resp = requests.get(url)
    resp_json = resp.json()
    report_b64 = resp_json.get("report")
    pubkey_b64 = resp_json.get("public_key")
    if not report_b64 or not pubkey_b64:
        print("服务器响应缺少必要信息！")
        return None
    report = base64.b64decode(report_b64)
    pubkey_pem = base64.b64decode(pubkey_b64)
    with open("temp_report", "wb") as f:
        f.write(report)
    verifier = AttestationReportVerifier("temp_report")
    if not verifier.verify_signature():
        print("认证报告签名验证失败，服务器不可信！")
        os.remove("temp_report")
        return None
    parsed_report = verifier.parse_attestation_report(return_dict=True)
    userdata_hex = parsed_report.get("Userdata")
    pubkey_digest_calc = hashes.Hash(hashes.SHA256(), backend=default_backend())
    pubkey_digest_calc.update(pubkey_pem)
    calc_digest = pubkey_digest_calc.finalize().hex()
    if not userdata_hex or calc_digest.encode('utf-8').hex() != userdata_hex:
        print("认证报告中的userdata与公钥摘要不匹配，服务器不可信！")
        os.remove("temp_report")
        return None
    print("认证报告签名验证通过，公钥摘要验证通过，服务器可信。")
    os.remove("temp_report")
    try:
        public_key = serialization.load_pem_public_key(pubkey_pem, backend=default_backend())
        return public_key
    except Exception as e:
        print(f"加载公钥失败: {e}")
        return None

def secure_key_exchange(server_url: str, server_public_key):
    data_encryption_key = os.urandom(32)
    encrypted_key = server_public_key.encrypt(
        data_encryption_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")
    url = f"{server_url}/secure_key_exchange"
    resp = requests.post(url, json={"encrypted_key": encrypted_key_b64})
    resp_json = resp.json()
    if resp_json.get("status") != "success":
        print(f"密钥交换失败: {resp_json.get('message')}")
        return None
    print("密钥交换成功，服务端保存了数据加密密钥")
    return data_encryption_key

def register_face(server_url: str, image_path: str, encryption_key: bytes):
    url = f"{server_url}/register_encrypted"
    with open(image_path, "rb") as f:
        image_data = f.read()
    encrypted_image = encrypt_aes_gcm(image_data, encryption_key)
    encrypted_image_b64 = base64.b64encode(encrypted_image).decode("utf-8")
    payload = {"encrypted_image": encrypted_image_b64}
    resp = requests.post(url, json=payload)
    resp_json = resp.json()
    print("注册结果:", resp_json)
    if resp_json.get("status") == "success" and "encrypted_response" in resp_json:
        encrypted_response = base64.b64decode(resp_json["encrypted_response"])
        decrypted_response = decrypt_aes_gcm(encrypted_response, encryption_key)
        decrypted_json = json.loads(decrypted_response.decode("utf-8"))
        print("解密后的注册结果:", decrypted_json)
        return decrypted_json
    return resp_json

def recognize_face(server_url: str, image_path: str, encryption_key: bytes):
    url = f"{server_url}/recognize_encrypted"
    with open(image_path, "rb") as f:
        image_data = f.read()
    encrypted_image = encrypt_aes_gcm(image_data, encryption_key)
    encrypted_image_b64 = base64.b64encode(encrypted_image).decode("utf-8")
    payload = {"encrypted_image": encrypted_image_b64}
    resp = requests.post(url, json=payload)
    resp_json = resp.json()
    print("识别结果:", resp_json)
    if resp_json.get("status") == "success" and "encrypted_response" in resp_json:
        encrypted_response = base64.b64decode(resp_json["encrypted_response"])
        decrypted_response = decrypt_aes_gcm(encrypted_response, encryption_key)
        decrypted_json = json.loads(decrypted_response.decode("utf-8"))
        print("解密后的识别结果:", decrypted_json)
        return decrypted_json
    return resp_json

if __name__ == "__main__":
    SERVER_URL = f"http://{config.SERVER_HOST}:{config.SERVER_PORT}"
    server_public_key = client_auth_check(SERVER_URL)
    if server_public_key:
        data_encryption_key = secure_key_exchange(SERVER_URL, server_public_key)
        if data_encryption_key:
            print("\n现在使用共享的数据加密密钥进行安全通信...")
            print("\n=== 加密人脸注册 ===")
            register_face(SERVER_URL, config.IMAGE_REG_PATH, data_encryption_key)
            print("\n=== 加密人脸识别 ===")
            recognize_face(SERVER_URL, config.IMAGE_REC_PATH, data_encryption_key)
        else:
            print("密钥交换失败，无法进行安全通信")
    else:
        print("服务器认证失败") 