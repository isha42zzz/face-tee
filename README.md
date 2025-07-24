# 人脸识别与CSV远程认证系统

## 项目简介
本项目实现了一个基于Flask的人脸识别服务，并结合CSV远程认证机制，保障服务端可信性。客户端可远程认证服务端，并进行人脸注册与识别。**新增了端到端加密传输功能，确保人脸数据在传输过程中的安全性。**

## 依赖安装
```bash
pip install -r requirements.txt
```

## 数据库说明
- 默认使用SQLite数据库，文件名为`face_recognition.db`。
- 首次启动服务端会自动初始化数据库表。

## 服务端启动
```bash
python face_server.py
```
服务默认监听在`0.0.0.0:5123`。

## 客户端使用
客户端脚本`face_client.py`包含四步：
1. 远程认证服务端可信性
2. 安全密钥交换
3. 加密注册人脸
4. 加密识别人脸

直接运行：
```bash
python face_client.py
```

## 接口说明

### 1. 远程认证 `/auth_check`（GET）
- 功能：获取服务端CSV认证报告，客户端可验证其可信性。
- 返回：JSON，包含base64编码的认证报告和RSA公钥。

### 2. 安全密钥交换 `/secure_key_exchange`（POST）
- 功能：客户端使用服务器RSA公钥加密AES密钥，建立安全通信通道。
- 参数：`encrypted_key`（base64编码的加密AES密钥）
- 返回：JSON，确认密钥交换成功。

### 3. 加密人脸注册 `/register_encrypted`（POST）
- 功能：使用AES密钥加密传输人脸图片进行注册。
- 参数：`encrypted_image`（base64编码的加密图片数据）
- 返回：JSON，包含加密的注册结果。

### 4. 加密人脸识别 `/recognize_encrypted`（POST）
- 功能：使用AES密钥加密传输人脸图片进行识别。
- 参数：`encrypted_image`（base64编码的加密图片数据）
- 返回：JSON，包含加密的识别结果。

### 5. 传统接口（向后兼容）
- `/register`（POST）：传统的人脸注册接口
- `/recognize`（POST）：传统的人脸识别接口

## 安全特性

### 端到端加密
- **AES-GCM加密**：使用256位AES密钥和GCM模式，提供认证加密
- **密钥交换**：使用RSA-OAEP进行安全的密钥交换
- **数据完整性**：GCM模式提供数据完整性验证
- **前向保密**：每次会话使用新的随机密钥

### CSV远程认证
- **硬件可信性**：验证服务器运行在可信硬件环境
- **公钥绑定**：将服务器公钥绑定到认证报告中
- **防篡改**：使用数字签名确保认证报告完整性

## 示例流程
1. 启动服务端：
   ```bash
   python face_server.py
   ```
2. 运行客户端：
   ```bash
   python face_client.py
   ```
   - 首先进行远程认证，验证服务端可信性
   - 然后进行安全密钥交换，建立加密通道
   - 使用加密通道注册`images/personA_reg.jpg`中的人脸
   - 最后使用加密通道识别`images/personA_rec.jpg`中的人脸

## 测试加密功能
```bash
python test_encryption.py
```

## 目录结构
```
face-tee/
  ├── face_client.py         # 客户端脚本（支持加密传输）
  ├── face_server.py         # 服务端脚本（支持加密传输）
  ├── csv_attestation.py     # CSV认证相关逻辑
  ├── test_encryption.py     # 加密功能测试脚本
  ├── face_recognition.db    # 人脸特征数据库
  ├── images/                # 存放测试图片
  └── requirements.txt       # 依赖包列表
```

## 技术细节

### 加密流程
1. **密钥交换**：客户端生成随机AES密钥，用服务器RSA公钥加密后发送
2. **数据加密**：客户端使用AES-GCM加密图片数据
3. **安全传输**：加密数据通过HTTP传输
4. **数据解密**：服务器使用共享AES密钥解密数据
5. **响应加密**：服务器加密响应数据返回给客户端

### 安全优势
- **隐私保护**：人脸图片在传输过程中完全加密
- **防重放攻击**：每次加密使用随机IV
- **数据认证**：GCM模式确保数据完整性
- **密钥安全**：AES密钥通过RSA加密传输

## 注意事项
- 注册和识别图片需为清晰的人脸照片
- 若数据库不存在，服务端会自动创建
- CSV认证相关代码仅供学习交流
- 加密功能需要cryptography库支持
- 建议在生产环境中使用HTTPS传输