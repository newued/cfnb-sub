#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VLESS-over-WebSocket 真实握手验证器

用途：验证订阅里的节点不只是在 TLS/WS 层能连（101），
     而且后端真的认可该 UUID 并接受 VLESS 请求（会回吐数据）。

用法：
    python cloud/verify_vless.py <订阅文件> [验证数量]
"""
import os
import re
import ssl
import sys
import uuid
import socket
import struct
import base64

HOST = "xiaogoutiaowuji.pages.dev"
WS_PATH = "/"
NODE_UUID = "b04f91ee-39e5-4b7c-87cb-722b326ac009"
TIMEOUT = 8


def build_ws_frame(payload: bytes) -> bytes:
    """客户端必须 mask；构造单帧 binary"""
    header = bytearray()
    header.append(0x82)  # FIN + binary
    length = len(payload)
    mask_bit = 0x80
    if length < 126:
        header.append(mask_bit | length)
    elif length < 65536:
        header.append(mask_bit | 126)
        header.extend(struct.pack(">H", length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack(">Q", length))
    key = os.urandom(4)
    header.extend(key)
    masked = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


def build_vless_request(dest_host="1.1.1.1", dest_port=80, payload=b"") -> bytes:
    """
    VLESS 请求头：
      version(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + addr_type(1) + addr + payload
    """
    u = uuid.UUID(NODE_UUID)
    out = bytearray()
    out.append(0x00)
    out.extend(u.bytes)
    out.append(0x00)          # addon length
    out.append(0x01)          # command: TCP
    out.extend(struct.pack(">H", dest_port))
    out.append(0x01)          # addr type: IPv4
    out.extend(socket.inet_aton(dest_host))
    out.extend(payload)
    return bytes(out)


def recv_all(sock, max_bytes=512):
    chunks = b""
    while len(chunks) < max_bytes:
        try:
            b = sock.recv(max_bytes - len(chunks))
        except socket.timeout:
            break
        except Exception:  # noqa: BLE001
            break
        if not b:
            break
        chunks += b
    return chunks


def verify_one(ip, port):
    """返回 (ok: bool, detail: str)"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=HOST) as s:
                s.settimeout(TIMEOUT)
                ws_key = base64.b64encode(os.urandom(16)).decode()
                req = (
                    f"GET {WS_PATH} HTTP/1.1\r\n"
                    f"Host: {HOST}\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    "Sec-WebSocket-Version: 13\r\n"
                    "User-Agent: Mozilla/5.0\r\n\r\n"
                )
                s.sendall(req.encode())
                head = recv_all(s, 256)
                if b"101" not in head.split(b"\r\n", 1)[0]:
                    return False, f"WS 未升级: {head.split(chr(13).encode())[0][:40]!r}"

                # 发送 VLESS 请求：访问 1.1.1.1:80 并附带 HTTP 请求
                vless = build_vless_request(
                    "1.1.1.1", 80,
                    b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n",
                )
                s.sendall(build_ws_frame(vless))
                s.settimeout(6)
                data = recv_all(s, 1024)

        if not data:
            return False, "无响应（UUID 可能不被认可，或目标不可达）"
        # WS 帧头 + VLESS 响应头(version + addon_len) 之后才是真实数据
        if len(data) > 3:
            return True, f"收到 {len(data)} 字节数据"
        return False, f"响应过短: {data[:16]!r}"
    except Exception as e:  # noqa: BLE001
        return False, f"异常: {type(e).__name__}: {e}"


def parse_nodes(path):
    nodes = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("vless://"):
                continue
            m = re.search(r"@([0-9.]+):(\d+)", line)
            if m:
                nodes.append((m.group(1), int(m.group(2))))
    return nodes


def main():
    if len(sys.argv) < 2:
        print("用法: python verify_vless.py <订阅文件> [数量]")
        return 1
    sub_file = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    nodes = parse_nodes(sub_file)[:limit]
    if not nodes:
        print("未解析到节点")
        return 1

    print(f"=== VLESS 真实握手验证（前 {len(nodes)} 个节点）===")
    ok = 0
    for i, (ip, port) in enumerate(nodes, 1):
        good, detail = verify_one(ip, port)
        if good:
            ok += 1
        print(f"  {i:2d}. {ip}:{port} -> {'PASS' if good else 'FAIL'} | {detail}")

    print(f"=== 结果: {ok}/{len(nodes)} 通过 VLESS 层验证 ===")
    return 0 if ok > 0 else 2


if __name__ == "__main__":
    sys.exit(main())
