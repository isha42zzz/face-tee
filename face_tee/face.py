import face_recognition
import numpy as np
from typing import List
import io

def extract_face_encoding(image_bytes: bytes) -> np.ndarray:
    """从图片字节流中提取人脸特征编码"""
    image = face_recognition.load_image_file(io.BytesIO(image_bytes))
    face_locations = face_recognition.face_locations(image)
    face_encodings = face_recognition.face_encodings(image, face_locations)
    if not face_encodings:
        return None
    return face_encodings[0]

def compare_faces(known_encodings: List[np.ndarray], face_encoding: np.ndarray, tolerance: float = 0.6) -> int:
    """比对人脸，返回匹配索引，未匹配返回-1"""
    if not known_encodings:
        return -1
    matches = face_recognition.compare_faces(known_encodings, face_encoding, tolerance)
    if True in matches:
        return matches.index(True)
    return -1 