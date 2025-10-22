# 基于TrustFlow快速搭建密态大模型推理服务

**Tips**
本文仅作为实验教程，请勿在生产环境直接使用。

本文示例使用的是模拟模式，如果需要在真实TEE环境下运行，请自行修改docker-compose.yml的相关配置项。

**注意，本教程假设您的服务器有GPU，若不满足，您可以自行修改docker-compose.yml的vllm-openai部署，改成支持CPU的推理引擎**

## 第一步：生成私钥和证书

为了方便测试，我们可以自生成一对私钥和证书。


1. 生成私钥

```bash
openssl genrsa -out app.key 3072
```
2. 基于私钥生成自签证书

```bash
openssl req -x509 -new -nodes -key app.key -sha256 -days 3650 -out app.crt
```
3. 私钥和证书需要放在`shared/deploy/`目录下。

```bash
mv app.key shared/deploy/app.key
mv app.crt shared/deploy/app.crt
```

## 第二步：启动容器

```bash
docker compose up -d
```

顺利的话，vLLM服务已经被拉起（端口为50001），默认部署`Qwen/Qwen3-0.6B`模型。

如果需要部署其他模型，您可以修改`docker-compose.yml`。

## 第三步：测试vLLM服务

我们先安装依赖

```bash
pip install -r requirements.txt
```

执行测试脚本，脚本会向vLLM服务发送聊天内容并获取回答。
```bash
python jwe_client.py
```