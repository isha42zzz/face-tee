# server.py
import sqlite3
import numpy as np
import face_recognition
from flask import Flask, request, jsonify, g
import uuid
import json
import logging
import io
from typing import List, Tuple, Optional, Any, Dict

# --- 配置 ---
DATABASE_NAME = "face_database.db"
FACE_DISTANCE_THRESHOLD = 0.6  # 人脸识别阈值

# 日志配置
logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- 工具函数 ---
def api_response(
    status: str, message: str, data: Optional[Any] = None, http_code: int = 200
):
    resp = {"status": status, "message": message}
    if data is not None:
        resp["data"] = data
    return jsonify(resp), http_code

# --- 全局异常处理 ---
@app.errorhandler(Exception)
def handle_exception(e: Exception):
    logger.error(f"Unhandled Exception: {e}")
    return api_response("error", f"Internal server error: {e}", http_code=500)

# --- 数据库操作 ---
def init_db() -> None:
    """初始化数据库，创建存储人脸编码的表"""
    db = sqlite3.connect(DATABASE_NAME)
    cursor = db.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS registered_faces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_id TEXT UNIQUE NOT NULL,
            encoding TEXT NOT NULL
        )
        """
    )
    db.commit()
    db.close()

def store_face_encoding(person_id: str, encoding: np.ndarray) -> bool:
    """
    将人脸编码存储到数据库。
    encoding (np.ndarray): 128维人脸编码。
    """
    try:
        db = sqlite3.connect(DATABASE_NAME)
        cursor = db.cursor()
        encoding_json = json.dumps(encoding.tolist())
        cursor.execute(
            "INSERT INTO registered_faces (person_id, encoding) VALUES (?, ?)",
            (person_id, encoding_json),
        )
        db.commit()
        db.close()
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"person_id {person_id} already exists.")
        return False
    except Exception as e:
        logger.error(f"Failed to store face encoding: {e}")
        return False

def load_all_face_encodings() -> Tuple[List[np.ndarray], List[str]]:
    """
    从数据库加载所有已注册的人脸编码及其对应的person_id。
    返回: (known_face_encodings: list[np.ndarray], known_person_ids: list[str])
    """
    db = sqlite3.connect(DATABASE_NAME)
    cursor = db.cursor()
    cursor.execute("SELECT person_id, encoding FROM registered_faces")
    rows = cursor.fetchall()
    db.close()
    known_face_encodings = []
    known_person_ids = []
    for row in rows:
        person_id = row[0]
        encoding = np.array(json.loads(row[1]))
        known_person_ids.append(person_id)
        known_face_encodings.append(encoding)
    return known_face_encodings, known_person_ids

# --- 人脸处理函数 ---
def process_image_for_faces(
    image_bytes: bytes,
) -> Tuple[List[np.ndarray], List[Any], Optional[str]]:
    """
    从图片二进制流检测人脸并提取128维编码。
    返回: (list[face_encoding], list[face_location], error_msg)
    """
    try:
        image = face_recognition.load_image_file(io.BytesIO(image_bytes))
        face_locations = face_recognition.face_locations(image)
        face_encodings = face_recognition.face_encodings(image, face_locations)
        return face_encodings, face_locations, None
    except Exception as e:
        logger.error(f"Error loading image: {e}")
        return [], [], f"Error loading image: {e}"

# --- 注册/识别流程复用 ---
def handle_face_image(
    image_bytes: bytes,
    known_face_encodings: List[np.ndarray],
    known_person_ids: List[str],
    register: bool = False
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    统一处理注册和识别流程。
    返回：(结果列表, 注册数, 跳过数)
    """
    face_encodings, face_locations, error_msg = process_image_for_faces(image_bytes)
    results = []
    registered_count = 0
    skipped_count = 0
    for i, face_encoding in enumerate(face_encodings):
        is_known = False
        person_id_found = None
        if known_face_encodings:
            matches = face_recognition.compare_faces(
                known_face_encodings,
                face_encoding,
                tolerance=FACE_DISTANCE_THRESHOLD,
            )
            face_distances = face_recognition.face_distance(
                known_face_encodings, face_encoding
            )
            if True in matches:
                best_match_index = np.argmin(face_distances)
                person_id_found = known_person_ids[best_match_index]
                is_known = True
        if register:
            if is_known:
                skipped_count += 1
                results.append(
                    {
                        "face_index": i,
                        "status": "skipped",
                        "reason": "Face already registered",
                        "person_id": person_id_found,
                        "location": face_locations[i],
                    }
                )
            else:
                new_person_id = str(uuid.uuid4())
                if store_face_encoding(new_person_id, face_encoding):
                    registered_count += 1
                    results.append(
                        {
                            "face_index": i,
                            "status": "registered",
                            "person_id": new_person_id,
                            "location": face_locations[i],
                        }
                    )
                else:
                    results.append(
                        {
                            "face_index": i,
                            "status": "error",
                            "reason": "Failed to store face encoding",
                            "location": face_locations[i],
                        }
                    )
        else:
            if is_known:
                face_distances = face_recognition.face_distance(
                    known_face_encodings, face_encoding
                )
                best_match_index = np.argmin(face_distances)
                confidence = float(1 - face_distances[best_match_index])
                results.append(
                    {
                        "face_index": i,
                        "person_id": person_id_found,
                        "confidence": confidence,
                        "location": face_locations[i],
                    }
                )
            else:
                results.append(
                    {
                        "face_index": i,
                        "person_id": "Unknown Person",
                        "confidence": 0.0,
                        "location": face_locations[i],
                    }
                )
    return results, registered_count, skipped_count

# --- Flask API 端点 ---
@app.route("/")
def index():
    return api_response("success", "人脸识别服务运行中！")

@app.route("/auth_check", methods=["GET"])
def auth_check():
    """
    阶段 (1) 客户端远程认证服务端是否可信
    此阶段通过海光CSV远程认证执行，暂不实现。
    """
    return api_response("success", "Server authentication simulated and passed.")

@app.route("/register", methods=["POST"])
def register_face():
    if "image" not in request.files:
        return api_response("error", "No image file provided.", http_code=400)
    file = request.files["image"]
    if file.filename == "":
        return api_response("error", "No selected file.", http_code=400)
    image_bytes = file.read()
    known_face_encodings, known_person_ids = load_all_face_encodings()
    results, registered_count, skipped_count = handle_face_image(
        image_bytes, known_face_encodings, known_person_ids, register=True
    )
    if not results:
        return api_response("error", "No face detected.")
    # 只处理第一张人脸
    first_result = results[0]
    if first_result["status"] == "registered":
        return api_response("success", "Registered", data={"person_id": first_result["person_id"]})
    elif first_result["status"] == "skipped":
        return api_response("success", "Already registered", data={"person_id": first_result["person_id"]})
    else:
        return api_response("error", first_result.get("reason", "Unknown error"))

@app.route("/recognize", methods=["POST"])
def recognize_face():
    if "image" not in request.files:
        return api_response("error", "No image file provided.", http_code=400)
    file = request.files["image"]
    if file.filename == "":
        return api_response("error", "No selected file.", http_code=400)
    image_bytes = file.read()
    known_face_encodings, known_person_ids = load_all_face_encodings()
    if not known_face_encodings:
        return api_response("error", "No faces registered yet. Cannot perform recognition.")
    results, _, _ = handle_face_image(
        image_bytes, known_face_encodings, known_person_ids, register=False
    )
    if not results:
        return api_response("error", "No face detected.")
    # 只处理第一张人脸
    first_result = results[0]
    if first_result["person_id"] != "Unknown Person":
        return api_response("success", "Recognized", data={"person_id": first_result["person_id"]})
    else:
        return api_response("error", "Unknown Person")

# --- 启动入口 ---
if __name__ == "__main__":
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized.")
    logger.info("Starting Flask server...")
    app.run(host="0.0.0.0", port=5123, debug=False)
