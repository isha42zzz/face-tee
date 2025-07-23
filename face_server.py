# face_server.py
import sqlite3
import numpy as np
import face_recognition
from flask import Flask, request, jsonify
import uuid
import base64
from csv_attestation import AttestationReportProducor
import io

DATABASE_NAME = "face_database.db"
FACE_DISTANCE_THRESHOLD = 0.8

app = Flask(__name__)


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
        producer = AttestationReportProducor()
        report = producer.report
        report_b64 = base64.b64encode(report).decode("utf-8")
        return jsonify(
            {
                "status": "success",
                "message": "Attestation report generated.",
                "report": report_b64,
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
    except:
        return jsonify({"status": "error", "message": "Error loading image."}), 400
    if not face_encodings:
        return jsonify({"status": "error", "message": "No face detected."}), 400
    known_face_encodings, known_person_ids = load_all_face_encodings()
    face_encoding = face_encodings[0]
    if known_face_encodings:
        matches = face_recognition.compare_faces(
            known_face_encodings, face_encoding, tolerance=FACE_DISTANCE_THRESHOLD
        )
        if True in matches:
            idx = matches.index(True)
            return jsonify(
                {
                    "status": "success",
                    "message": "Already registered",
                    "person_id": known_person_ids[idx],
                }
            )
    new_person_id = str(uuid.uuid4())
    if store_face_encoding(new_person_id, face_encoding):
        return jsonify(
            {"status": "success", "message": "Registered", "person_id": new_person_id}
        )
    else:
        return (
            jsonify({"status": "error", "message": "Failed to store face encoding."}),
            500,
        )


@app.route("/recognize", methods=["POST"])
def recognize_face():
    if "image" not in request.files:
        return jsonify({"status": "error", "message": "No image file provided."}), 400
    file = request.files["image"]
    image_bytes = file.read()
    try:
        image = face_recognition.load_image_file(io.BytesIO(image_bytes))
        face_locations = face_recognition.face_locations(image)
        face_encodings = face_recognition.face_encodings(image, face_locations)
    except:
        return jsonify({"status": "error", "message": "Error loading image."}), 400
    if not face_encodings:
        return jsonify({"status": "error", "message": "No face detected."}), 400
    known_face_encodings, known_person_ids = load_all_face_encodings()
    if not known_face_encodings:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "No faces registered yet. Cannot perform recognition.",
                }
            ),
            400,
        )
    face_encoding = face_encodings[0]
    matches = face_recognition.compare_faces(
        known_face_encodings, face_encoding, tolerance=FACE_DISTANCE_THRESHOLD
    )
    if True in matches:
        idx = matches.index(True)
        return jsonify(
            {
                "status": "success",
                "message": "Recognized",
                "person_id": known_person_ids[idx],
            }
        )
    else:
        return jsonify({"status": "error", "message": "Unknown Person"}), 400


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5123, debug=False)
