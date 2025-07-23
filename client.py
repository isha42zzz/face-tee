# client.py

import requests
import os
import json # 用于美化打印JSON响应

# --- 配置 ---
SERVER_URL = "http://127.0.0.1:5123" # 如果服务器运行在不同的IP或端口，请修改这里


def client_auth_check():
    """
    阶段 (1) 客户端远程认证服务端是否可信 (占位符)
    """
    print("\n--- 阶段 1: 客户端远程认证服务端 ---")
    try:
        response = requests.get(f"{SERVER_URL}/auth_check")
        response.raise_for_status() # 对200以外的状态码抛出HTTPError
        print("服务器认证结果:")
        print(json.dumps(response.json(), indent=4, ensure_ascii=False))
        return response.json()
    except requests.exceptions.ConnectionError:
        print(f"错误: 无法连接到服务器 {SERVER_URL}。请确认服务器是否已运行。")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"HTTP错误: {e}")
        print(f"服务器返回: {response.text}")
        return None
    except Exception as e:
        print(f"发生未知错误: {e}")
        return None

def register_face(image_path: str):
    """
    阶段 (2) 客户端向服务器注册人脸
    """
    print(f"\n--- 阶段 2: 注册人脸: {image_path} ---")
    if not os.path.exists(image_path):
        print(f"错误: 图片文件未找到 - {image_path}")
        return None

    try:
        with open(image_path, 'rb') as f:
            files = {'image': (os.path.basename(image_path), f, 'image/jpeg')}
            response = requests.post(f"{SERVER_URL}/register", files=files)
            response.raise_for_status()
            print("注册结果:")
            print(json.dumps(response.json(), indent=4, ensure_ascii=False))
            return response.json()
    except requests.exceptions.ConnectionError:
        print(f"错误: 无法连接到服务器 {SERVER_URL}。请确认服务器是否已运行。")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"HTTP错误: {e}")
        print(f"服务器返回: {response.text}")
        return None
    except Exception as e:
        print(f"发生未知错误: {e}")
        return None

def recognize_face(image_path: str):
    """
    阶段 (3) 客户端向服务端请求人脸识别
    """
    print(f"\n--- 阶段 3: 识别图片中的人脸: {image_path} ---")
    if not os.path.exists(image_path):
        print(f"错误: 图片文件未找到 - {image_path}")
        return None

    try:
        with open(image_path, 'rb') as f:
            files = {'image': (os.path.basename(image_path), f, 'image/jpeg')}
            response = requests.post(f"{SERVER_URL}/recognize", files=files)
            response.raise_for_status()
            print("识别结果:")
            print(json.dumps(response.json(), indent=4, ensure_ascii=False))
            return response.json()
    except requests.exceptions.ConnectionError:
        print(f"错误: 无法连接到服务器 {SERVER_URL}。请确认服务器是否已运行。")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"HTTP错误: {e}")
        print(f"服务器返回: {response.text}")
        return None
    except Exception as e:
        print(f"发生未知错误: {e}")
        return None

# --- 示例使用 ---

if __name__ == '__main__':
    # --- 准备测试图片 ---
    IMAGE_DIR = "images"
    if not os.path.exists(IMAGE_DIR):
        print(f"请创建文件夹 '{IMAGE_DIR}' 并在其中放入测试图片文件。")
        exit()

    person_a_register_img = os.path.join(IMAGE_DIR, "personA_reg.jpg")
    person_a_recognize_img = os.path.join(IMAGE_DIR, "personA_rec.jpg")

    # 1. 模拟认证检查
    client_auth_check()

    # 2. 注册人脸 A
    register_face(person_a_register_img)

    # 3. 识别已注册的人脸 A
    recognize_face(person_a_recognize_img)

    print("\n测试流程执行完毕。")

