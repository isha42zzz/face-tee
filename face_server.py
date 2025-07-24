# face_server.py
import sqlite3
import numpy as np
import face_recognition
from flask import Flask, request, jsonify
import uuid
import base64
from csv_attestation import AttestationReportProducor
import io
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json

app = Flask(__name__)
DATABASE_NAME = "face_recognition.db"

# 全局变量存储当前会话的加密密钥
session_encryption_key = None


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


def encrypt_data(data, key):
    """使用AES-GCM加密数据"""
    import os
    # 生成随机IV
    iv = os.urandom(12)
    
    # 创建AES-GCM加密器
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 加密数据
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # 返回IV + 密文 + 认证标签
    return iv + encryptor.tag + ciphertext


# 每次启动时直接生成新的RSA密钥对
def get_server_keys():
    # 生成新的RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # 将公钥序列化为PEM格式
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key, public_key, public_key_pem


def init_db():
    db = sqlite3.connect(DATABASE_NAME)
    cursor = db.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS registered_faces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_id TEXT UNIQUE NOT NULL,
            encoding BLOB NOT NULL
        )
        """
    )
    db.commit()
    db.close()


def store_face_encoding(person_id, encoding):
    try:
        db = sqlite3.connect(DATABASE_NAME)
        cursor = db.cursor()
        encoding_bytes = encoding.astype(np.float64).tobytes()
        cursor.execute(
            "INSERT INTO registered_faces (person_id, encoding) VALUES (?, ?)",
            (person_id, encoding_bytes),
        )
        db.commit()
        success = cursor.rowcount > 0
        db.close()
        return success
    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        print(f"Error storing face encoding: {e}")
        return False


def load_all_face_encodings():
    db = sqlite3.connect(DATABASE_NAME)
    cursor = db.cursor()
    cursor.execute("SELECT person_id, encoding FROM registered_faces")
    rows = cursor.fetchall()
    db.close()
    known_face_encodings = []
    known_person_ids = []
    for row in rows:
        person_id = row[0]
        encoding_bytes = row[1]
        encoding = np.frombuffer(encoding_bytes, dtype=np.float64)
        known_person_ids.append(person_id)
        known_face_encodings.append(encoding)
    return known_face_encodings, known_person_ids


@app.route("/auth_check", methods=["GET"])
def auth_check():
    try:
        # 获取服务器密钥对
        _, _, public_key_pem = get_server_keys()

        # 计算公钥的摘要作为userdata
        public_key_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        public_key_digest.update(public_key_pem)
        digest_value = public_key_digest.finalize()
        userdata = digest_value.hex()

        # 生成包含公钥摘要的认证报告
        producer = AttestationReportProducor(userdata)
        report = producer.report
        report_b64 = base64.b64encode(report).decode("utf-8")

        # 将公钥编码为base64字符串
        pubkey_b64 = base64.b64encode(public_key_pem).decode("utf-8")

        return jsonify(
            {
                "status": "success",
                "message": "Attestation report generated.",
                "report": report_b64,
                "public_key": pubkey_b64,
            }
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": f"Failed to generate attestation report: {e}",
                }
            ),
            500,
        )


@app.route("/register", methods=["POST"])
def register_face():
    if "image" not in request.files:
        return jsonify({"status": "error", "message": "No image file provided."}), 400

    file = request.files["image"]
    image_bytes = file.read()

    try:
        image = face_recognition.load_image_file(io.BytesIO(image_bytes))
        face_locations = face_recognition.face_locations(image)
        face_encodings = face_recognition.face_encodings(image, face_locations)

        if not face_encodings:
            return (
                jsonify({"status": "error", "message": "No face detected in image."}),
                400,
            )

        face_encoding = face_encodings[0]

        # 检查是否已经注册过
        known_face_encodings, known_person_ids = load_all_face_encodings()
        if known_face_encodings:
            matches = face_recognition.compare_faces(
                known_face_encodings, face_encoding, tolerance=0.6
            )
            if True in matches:
                idx = matches.index(True)
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Face already registered.",
                            "person_id": known_person_ids[idx],
                        }
                    ),
                    400,
                )

        # 注册新的人脸
        new_person_id = str(uuid.uuid4())
        if store_face_encoding(new_person_id, face_encoding):
            return jsonify(
                {
                    "status": "success",
                    "message": "Face registered successfully.",
                    "person_id": new_person_id,
                }
            )
        else:
            return (
                jsonify(
                    {"status": "error", "message": "Failed to store face encoding."}
                ),
                500,
            )

    except Exception as e:
        return (
            jsonify(
                {"status": "error", "message": f"Error processing image: {str(e)}"}
            ),
            400,
        )


@app.route("/recognize", methods=["POST"])
def recognize():
    if "image" not in request.files:
        return jsonify({"status": "error", "message": "No image file provided."}), 400

    file = request.files["image"]
    image_bytes = file.read()

    try:
        image = face_recognition.load_image_file(io.BytesIO(image_bytes))
        face_locations = face_recognition.face_locations(image)
        face_encodings = face_recognition.face_encodings(image, face_locations)

        if not face_encodings:
            return (
                jsonify({"status": "error", "message": "No face detected in image."}),
                400,
            )

        face_encoding = face_encodings[0]
        known_face_encodings, known_person_ids = load_all_face_encodings()

        if not known_face_encodings:
            return (
                jsonify({"status": "error", "message": "No registered faces found."}),
                400,
            )

        matches = face_recognition.compare_faces(
            known_face_encodings, face_encoding, tolerance=0.6
        )

        if True in matches:
            idx = matches.index(True)
            return jsonify(
                {
                    "status": "success",
                    "message": "Face recognized.",
                    "person_id": known_person_ids[idx],
                }
            )
        else:
            return jsonify({"status": "error", "message": "Face not recognized."}), 404

    except Exception as e:
        return (
            jsonify(
                {"status": "error", "message": f"Error processing image: {str(e)}"}
            ),
            400,
        )


@app.route("/register_encrypted", methods=["POST"])
def register_face_encrypted():
    global session_encryption_key
    
    if not session_encryption_key:
        return jsonify({"status": "error", "message": "No encryption key established"}), 400
    
    data = request.get_json()
    if not data or "encrypted_image" not in data:
        return jsonify({"status": "error", "message": "Missing encrypted_image"}), 400

    try:
        # 解密图片数据
        encrypted_image = base64.b64decode(data["encrypted_image"])
        image_bytes = decrypt_data(encrypted_image, session_encryption_key)
        
        # 处理图片
        image = face_recognition.load_image_file(io.BytesIO(image_bytes))
        face_locations = face_recognition.face_locations(image)
        face_encodings = face_recognition.face_encodings(image, face_locations)

        if not face_encodings:
            response_data = {"status": "error", "message": "No face detected in image."}
        else:
            face_encoding = face_encodings[0]

            # 检查是否已经注册过
            known_face_encodings, known_person_ids = load_all_face_encodings()
            if known_face_encodings:
                matches = face_recognition.compare_faces(
                    known_face_encodings, face_encoding, tolerance=0.6
                )
                if True in matches:
                    idx = matches.index(True)
                    response_data = {
                        "status": "error",
                        "message": "Face already registered.",
                        "person_id": known_person_ids[idx],
                    }
                else:
                    # 注册新的人脸
                    new_person_id = str(uuid.uuid4())
                    if store_face_encoding(new_person_id, face_encoding):
                        response_data = {
                            "status": "success",
                            "message": "Face registered successfully.",
                            "person_id": new_person_id,
                        }
                    else:
                        response_data = {
                            "status": "error",
                            "message": "Failed to store face encoding."
                        }
            else:
                # 没有已注册的人脸，直接注册
                new_person_id = str(uuid.uuid4())
                if store_face_encoding(new_person_id, face_encoding):
                    response_data = {
                        "status": "success",
                        "message": "Face registered successfully.",
                        "person_id": new_person_id,
                    }
                else:
                    response_data = {
                        "status": "error",
                        "message": "Failed to store face encoding."
                    }

        # 加密响应
        response_json = json.dumps(response_data)
        encrypted_response = encrypt_data(response_json.encode("utf-8"), session_encryption_key)
        encrypted_response_b64 = base64.b64encode(encrypted_response).decode("utf-8")
        
        return jsonify({
            "status": "success",
            "encrypted_response": encrypted_response_b64
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error processing encrypted image: {str(e)}"
        }), 400


@app.route("/recognize_encrypted", methods=["POST"])
def recognize_encrypted():
    global session_encryption_key
    
    if not session_encryption_key:
        return jsonify({"status": "error", "message": "No encryption key established"}), 400
    
    data = request.get_json()
    if not data or "encrypted_image" not in data:
        return jsonify({"status": "error", "message": "Missing encrypted_image"}), 400

    try:
        # 解密图片数据
        encrypted_image = base64.b64decode(data["encrypted_image"])
        image_bytes = decrypt_data(encrypted_image, session_encryption_key)
        
        # 处理图片
        image = face_recognition.load_image_file(io.BytesIO(image_bytes))
        face_locations = face_recognition.face_locations(image)
        face_encodings = face_recognition.face_encodings(image, face_locations)

        if not face_encodings:
            response_data = {"status": "error", "message": "No face detected in image."}
        else:
            face_encoding = face_encodings[0]
            known_face_encodings, known_person_ids = load_all_face_encodings()

            if not known_face_encodings:
                response_data = {"status": "error", "message": "No registered faces found."}
            else:
                matches = face_recognition.compare_faces(
                    known_face_encodings, face_encoding, tolerance=0.6
                )

                if True in matches:
                    idx = matches.index(True)
                    response_data = {
                        "status": "success",
                        "message": "Face recognized.",
                        "person_id": known_person_ids[idx],
                    }
                else:
                    response_data = {"status": "error", "message": "Face not recognized."}

        # 加密响应
        response_json = json.dumps(response_data)
        encrypted_response = encrypt_data(response_json.encode("utf-8"), session_encryption_key)
        encrypted_response_b64 = base64.b64encode(encrypted_response).decode("utf-8")
        
        return jsonify({
            "status": "success",
            "encrypted_response": encrypted_response_b64
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error processing encrypted image: {str(e)}"
        }), 400


@app.route("/secure_key_exchange", methods=["POST"])
def secure_key_exchange():
    global session_encryption_key
    
    try:
        data = request.get_json()
        if not data or "encrypted_key" not in data:
            return jsonify({"status": "error", "message": "Missing encrypted_key"}), 400

        # 获取服务器私钥
        private_key, _, _ = get_server_keys()

        # 解码并解密数据加密密钥
        encrypted_key = base64.b64decode(data["encrypted_key"])
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 保存会话加密密钥
        session_encryption_key = decrypted_key

        return jsonify(
            {
                "status": "success",
                "message": "Secure key exchange completed",
                "decrypted_key": base64.b64encode(decrypted_key).decode("utf-8"),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {"status": "error", "message": f"Secure key exchange failed: {str(e)}"}
            ),
            500,
        )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5123, debug=False)
