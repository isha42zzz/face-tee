# 基础镜像
FROM python:3.9-slim

# 安装系统依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libssl-dev \
        libffi-dev \
        libsqlite3-dev \
        libopencv-dev \
        python3-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# 升级pip
RUN pip install --upgrade pip

# 拷贝项目文件
WORKDIR /app
COPY . /app

# 安装Python依赖
RUN pip install -r requirements.txt