# 人脸识别与CSV远程认证系统

## 项目简介
本项目实现了一个基于Flask的人脸识别服务，并结合CSV远程认证机制，保障服务端可信性。客户端可远程认证服务端，并进行人脸注册与识别。

## 依赖安装
```bash
pip install -r requirements.txt
```

## 数据库说明
- 默认使用SQLite数据库，文件名为`face_database.db`。
- 首次启动服务端会自动初始化数据库表。

## 服务端启动
```bash
python face_server.py
```
服务默认监听在`0.0.0.0:5123`。

## 客户端使用
客户端脚本`face_client.py`包含三步：
1. 远程认证服务端可信性
2. 注册人脸
3. 识别人脸

直接运行：
```bash
python face_client.py
```

## 接口说明
### 1. 远程认证 `/auth_check`（GET）
- 功能：获取服务端CSV认证报告，客户端可验证其可信性。
- 返回：JSON，包含base64编码的认证报告。

### 2. 人脸注册 `/register`（POST）
- 参数：`image`（表单文件，需包含人脸）
- 功能：注册新的人脸特征，若已注册则返回已注册信息。
- 返回：JSON，包含注册状态、person_id等。

### 3. 人脸识别 `/recognize`（POST）
- 参数：`image`（表单文件，需包含人脸）
- 功能：识别上传人脸，返回识别结果。
- 返回：JSON，包含识别状态、person_id等。

## 示例流程
1. 启动服务端：
   ```bash
   python face_server.py
   ```
2. 运行客户端：
   ```bash
   python face_client.py
   ```
   - 首先进行远程认证，验证服务端可信性。
   - 然后注册`images/personA_reg.jpg`中的人脸。
   - 最后识别`images/personA_rec.jpg`中的人脸。

## 目录结构
```
face-tee/
  ├── face_client.py         # 客户端脚本
  ├── face_server.py         # 服务端脚本
  ├── csv_attestation.py     # CSV认证相关逻辑
  ├── face_database.db       # 人脸特征数据库
  ├── images/                # 存放测试图片
  └── requirements.txt       # 依赖包列表
```

## 注意事项
- 注册和识别图片需为清晰的人脸照片。
- 若数据库不存在，服务端会自动创建。
- CSV认证相关代码仅供学习交流。