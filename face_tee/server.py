import uuid
import base64
import json
from flask import Flask, request, jsonify
from . import db, face, crypto_utils, attestation, config
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from .crypto_utils import get_server_keys

app = Flask(__name__)
session_encryption_key = None
# session_encryption_key = b'\x01' * 32  # 固定密钥，用于测试非csv环境下的加密注册和识别人脸


@app.route("/auth_check", methods=["GET"])
def auth_check():
    try:
        _, _, public_key_pem = get_server_keys()
        public_key_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        public_key_digest.update(public_key_pem)
        digest_value = public_key_digest.finalize()
        userdata = digest_value.hex()
        producer = attestation.AttestationReportProducor(userdata)
        report = producer.report
        report_b64 = base64.b64encode(report).decode("utf-8")
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


@app.route("/secure_key_exchange", methods=["POST"])
def secure_key_exchange():
    global session_encryption_key
    try:
        data = request.get_json()
        if not data or "encrypted_key" not in data:
            return jsonify({"status": "error", "message": "Missing encrypted_key"}), 400
        private_key, _, _ = get_server_keys()
        encrypted_key = base64.b64decode(data["encrypted_key"])
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        session_encryption_key = decrypted_key
        return jsonify(
            {"status": "success", "message": "Secure key exchange completed"}
        )
    except Exception as e:
        return (
            jsonify(
                {"status": "error", "message": f"Secure key exchange failed: {str(e)}"}
            ),
            500,
        )


@app.route("/register_encrypted", methods=["POST"])
def register_face_encrypted():
    global session_encryption_key
    if not session_encryption_key:
        return (
            jsonify({"status": "error", "message": "No encryption key established"}),
            400,
        )
    data = request.get_json()
    if not data or "encrypted_image" not in data:
        return jsonify({"status": "error", "message": "Missing encrypted_image"}), 400
    try:
        encrypted_image = base64.b64decode(data["encrypted_image"])
        image_bytes = crypto_utils.decrypt_aes_gcm(
            encrypted_image, session_encryption_key
        )
        face_encoding = face.extract_face_encoding(image_bytes)
        if face_encoding is None:
            response_data = {"status": "error", "message": "No face detected in image."}
        else:
            known_face_encodings, known_person_ids = db.load_all_face_encodings()
            idx = face.compare_faces(known_face_encodings, face_encoding)
            if idx != -1:
                response_data = {
                    "status": "error",
                    "message": "Face already registered.",
                    "person_id": known_person_ids[idx],
                }
            else:
                new_person_id = str(uuid.uuid4())
                if db.store_face_encoding(new_person_id, face_encoding):
                    response_data = {
                        "status": "success",
                        "message": "Face registered successfully.",
                        "person_id": new_person_id,
                    }
                else:
                    response_data = {
                        "status": "error",
                        "message": "Failed to store face encoding.",
                    }
        response_json = json.dumps(response_data)
        encrypted_response = crypto_utils.encrypt_aes_gcm(
            response_json.encode("utf-8"), session_encryption_key
        )
        encrypted_response_b64 = base64.b64encode(encrypted_response).decode("utf-8")
        return jsonify(
            {"status": "success", "encrypted_response": encrypted_response_b64}
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": f"Error processing encrypted image: {str(e)}",
                }
            ),
            400,
        )


@app.route("/recognize_encrypted", methods=["POST"])
def recognize_encrypted():
    global session_encryption_key
    if not session_encryption_key:
        return (
            jsonify({"status": "error", "message": "No encryption key established"}),
            400,
        )
    data = request.get_json()
    if not data or "encrypted_image" not in data:
        return jsonify({"status": "error", "message": "Missing encrypted_image"}), 400
    try:
        encrypted_image = base64.b64decode(data["encrypted_image"])
        image_bytes = crypto_utils.decrypt_aes_gcm(
            encrypted_image, session_encryption_key
        )
        face_encoding = face.extract_face_encoding(image_bytes)
        if face_encoding is None:
            response_data = {"status": "error", "message": "No face detected in image."}
        else:
            known_face_encodings, known_person_ids = db.load_all_face_encodings()
            idx = face.compare_faces(known_face_encodings, face_encoding)
            if idx != -1:
                response_data = {
                    "status": "success",
                    "message": "Face recognized.",
                    "person_id": known_person_ids[idx],
                }
            else:
                response_data = {"status": "error", "message": "Face not recognized."}
        response_json = json.dumps(response_data)
        encrypted_response = crypto_utils.encrypt_aes_gcm(
            response_json.encode("utf-8"), session_encryption_key
        )
        encrypted_response_b64 = base64.b64encode(encrypted_response).decode("utf-8")
        return jsonify(
            {"status": "success", "encrypted_response": encrypted_response_b64}
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": f"Error processing encrypted image: {str(e)}",
                }
            ),
            400,
        )


if __name__ == "__main__":
    db.init_db(config.DATABASE_NAME)
    app.run(host=config.SERVER_HOST, port=config.SERVER_PORT, debug=False)
