# face_client.py
import requests
import base64
from csv_attestation import AttestationReportVerifier

SERVER_URL = "http://127.0.0.1:5123"


def client_auth_check():
    url = f"{SERVER_URL}/auth_check"
    resp = requests.get(url)
    resp_json = resp.json()
    print(resp_json)
    report_b64 = resp_json.get("report")
    if report_b64:
        report = base64.b64decode(report_b64)
        verifier = AttestationReportVerifier(report)
        if verifier.verify_signature():
            print("认证报告签名验证通过，服务器可信。")
            verifier.parse_attestation_report()
        else:
            print("认证报告签名验证失败，服务器不可信！")


def register_face(image_path):
    url = f"{SERVER_URL}/register"
    with open(image_path, "rb") as f:
        files = {"image": f}
        resp = requests.post(url, files=files)
    print(resp.json())


def recognize_face(image_path):
    url = f"{SERVER_URL}/recognize"
    with open(image_path, "rb") as f:
        files = {"image": f}
        resp = requests.post(url, files=files)
    print(resp.json())


if __name__ == "__main__":
    # 1. 远程认证
    # client_auth_check()
    # 2. 注册
    register_face("images/personA_reg.jpg")
    # 3. 识别
    recognize_face("images/personA_rec.jpg")
