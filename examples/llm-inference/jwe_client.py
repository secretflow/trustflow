# Copyright 2025 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import base64
import json
import secrets

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

chat = "你好！"


def encode_base64(input_bytes: bytes) -> str:
    """
    对字节进行非pad的base64编码。
    urlsafe unpadded base64 encode

    Args:
        input_bytes: 待编码的字节。

    Returns:
        编码得到的字符串。
    """
    output_bytes = base64.urlsafe_b64encode(input_bytes)
    output_string = output_bytes.decode("ascii")
    return output_string.rstrip("=")


def decode_base64(input_string: str) -> bytes:
    """
    对输入的字符串进行base64解码
    urlsafe unpadded base64 decode
    """

    input_bytes = input_string.encode("ascii")
    input_len = len(input_bytes)
    padding = b"=" * (3 - ((input_len + 3) % 4))

    output_bytes = base64.b64decode(input_bytes + padding, altchars=b"-_")
    return output_bytes


def build_jwe(
    content: str,
    public_key_pem: bytes,
    data_key: bytes,
    iv: bytes,
    aad: bytes = b"",
) -> str:
    """
    构造JWE。

    Args:
        content: 待加密的内容。
        public_key_pem: 服务的公钥，pem格式。
        data_key: 16个字节长度的对称密钥。
        iv: 对称加密的Initialization Vector，长度为12字节。
        aad：对称加密的Additional Authenticated Data，一般可为空。

    Returns:
        json格式的JWE。
    """

    jwe_header = {
        "alg": "RSA-OAEP-256",
        "enc": "A128GCM",
    }

    # 对内容进行对称加密。
    encryptor = Cipher(
        algorithms.AES(data_key),
        modes.GCM(iv),
    ).encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(content.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    # 用服务公钥加密对称密钥
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_data_key = public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    jwe = {
        "protected": encode_base64(json.dumps(jwe_header).encode("utf-8")),
        "encrypted_key": encode_base64(encrypted_data_key),
        "iv": encode_base64(iv),
        "aad": encode_base64(aad),
        "ciphertext": encode_base64(ciphertext),
        "tag": encode_base64(tag),
    }

    return json.dumps(jwe)


def parse_jwe(
    jwe_str: str,
    data_key: bytes,
) -> str:
    """
    解析jwe

    Args:
        jwe_str: JWE的json字符串。
        data_key: 数据加密密钥。
    """
    jwe = json.loads(jwe_str)

    iv = decode_base64(jwe["iv"])
    ciphertext = decode_base64(jwe["ciphertext"])
    tag = decode_base64(jwe["tag"])
    aad = decode_base64(jwe["aad"])

    decryptor = Cipher(
        algorithms.AES(data_key),
        modes.GCM(iv, tag),
    ).decryptor()
    decryptor.authenticate_additional_data(aad)
    plain_text = decryptor.update(ciphertext) + decryptor.finalize()

    return plain_text.decode("utf-8")


def sha256(*args: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    assert (
        len(args) >= 1
    ), "At least one piece of data is involved in the calculation of hash."
    h.update(args[0])
    for arg in args[1:]:
        h.update(b".")
        h.update(arg)
    return h.finalize()


def main():
    # 1. GetRaCert
    ra_url = "http://127.0.0.1:50001/RaProxy/GetRaCert"
    nonce = secrets.token_hex(16)
    ra_response = requests.post(
        ra_url,
        headers={"Content-Type": "application/json"},
        data=json.dumps({"nonce": nonce}),
    )
    assert ra_response.status_code == 200, f"GetRaCert failed: {ra_response.text}"
    server_cert = ra_response.json().get("cert")
    ra_report = ra_response.json().get("attestation_report")

    # 2. Encrypted request
    llm_url = "http://127.0.0.1:50001/v1/chat/completions"
    message = {
        "model": "Qwen/Qwen3-0.6B",
        "messages": [{"role": "user", "content": chat}],
    }
    message = json.dumps(message)

    public_key_pem = (
        x509.load_pem_x509_certificate(server_cert.encode("utf-8"))
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    data_key = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    response = requests.post(
        llm_url,
        headers={"Content-Type": "application/json"},
        data=build_jwe(message, public_key_pem, data_key, iv),
    )
    assert response.status_code == 200, f"Failed to request llm: {response}"

    # 3. Parse encrypted response
    response_msg = parse_jwe(json.dumps(response.json()), data_key)
    response_msg = json.loads(response_msg)
    print("提问问题：", chat)
    print("思考内容：", response_msg["choices"][0]["message"]["reasoning_content"])
    print("回答内容：", response_msg["choices"][0]["message"]["content"])


if __name__ == "__main__":
    main()
