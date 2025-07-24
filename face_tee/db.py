import sqlite3
import numpy as np
from typing import List, Tuple
from . import config

def init_db(db_path: str = config.DATABASE_NAME):
    db = sqlite3.connect(db_path)
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

def store_face_encoding(person_id: str, encoding: np.ndarray, db_path: str = config.DATABASE_NAME) -> bool:
    try:
        db = sqlite3.connect(db_path)
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

def load_all_face_encodings(db_path: str = config.DATABASE_NAME) -> Tuple[List[np.ndarray], List[str]]:
    db = sqlite3.connect(db_path)
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