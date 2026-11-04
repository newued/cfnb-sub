#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CFNB 云端订阅生成器（在 GitHub Actions 中运行，不依赖本机）

流程：
  1. 并发抓取多个公开 Cloudflare 优选 IP 源
  2. 过滤：私有地址 / 屏蔽地区 / 非法格式
  3. 真实可用性筛选：TLS 握手 + WS 升级探测（在 GitHub Runner 上执行）
  4. 混合采样（CF 官方段 + 第三方中转，6 小时轮换种子保证不过度抖动）
  5. 生成 VLESS 订阅写入 sub_final.txt

退出码：0 成功写入；2 无可用节点（保留旧文件）
"""
import os
import re
import ssl
import sys
import json
import time
import base64
import random
import socket
import hashlib
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen

# ---------------- 配置 ----------------
SOURCES = [
    "https://zip.cm.edu.kg/all.txt",
    "https://countrymerge.pages.dev/all.txt",
    "https://cf.090227.xyz/cmcc-ip.txt",
    "https://raw.githubusercontent.com/cmliu/CloudFlareIPSelector/main/ip.txt",
]

TARGET_HOST = "xiaogoutiaowuji.pages.dev"
TARGET_PATH = "/"
UUID = "b04f91ee-39e5-4b7c-87cb-722b326ac009"

NODE_COUNT = 30
PREFERRED_PORT = 443
OTHER_PORTS = (2053, 2083, 2087, 2096, 8443)
BLOCKED_TAGS = {"CN", "IR", "KP", "CU", "RU", "VN", "PK", "BD", "SY", "SD"}

FETCH_TIMEOUT = 15
PROBE_TIMEOUT = 4
PROBE_WORKERS = 64
MAX_CANDIDATES = 700        # 参与探测的最大候选数（只收 101，通过率低，需大样本）
KEEP_FASTEST = 12           # 保留延迟最低的 N 个
OUTPUT = os.environ.get("SUB_OUTPUT", "sub_final.txt")

CF_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CF_NETS = [ipaddress.ip_network(c) for c in CF_CIDRS]


def log(msg):
    print(msg, flush=True)


def is_cf_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CF_NETS)


def fetch(url):
    try:
        req = Request(url, headers={"User-Agent": "cfnb-sub/2.0"})
        with urlopen(req, timeout=FETCH_TIMEOUT) as r:
            raw = r.read()
        return raw.decode("utf-8", "ignore"), None
    except Exception as e:  # noqa: BLE001
        return "", str(e)


IP_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")


def parse_all(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tag = ""
        body = line
        if "#" in line:
            body, tag = line.split("#", 1)
            tag = tag.strip()
            body = body.strip()
        m = IP_PORT_RE.search(body)
        if not m:
            continue
        ip = m.group(1)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_reserved:
            continue
        port = int(m.group(2)) if m.group(2) else 443
        if not (0 < port < 65536):
            port = 443
        if port != PREFERRED_PORT and port not in OTHER_PORTS:
            continue
        up = tag.upper()
        if up and any(b == up or b in up for b in BLOCKED_TAGS):
            continue
        out.append({"ip": ip, "port": port, "tag": (tag or "XX")[:8]})
    return out


def probe(node):
    """真实 VLESS-over-WS 探测：TLS 握手 + WebSocket 升级，只有 101 才算可用"""
    ip, port = node["ip"], node["port"]
    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=TARGET_HOST) as ssock:
                ssock.settimeout(PROBE_TIMEOUT)
                req = (
                    f"GET {TARGET_PATH} HTTP/1.1\r\n"
                    f"Host: {TARGET_HOST}\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                )
                ssock.sendall(req.encode())
                data = ssock.recv(256)
        if not data:
            return None
        status_line = data.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
        if not status_line.startswith("HTTP/"):
            return None
        parts = status_line.split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        # 仅 101 表示 WS 后端真实存在；403/404/200 都是边缘默认响应，节点不可用
        if code != 101:
            return None
        node["latency"] = int((time.time() - t0) * 1000)
        node["status"] = code
        return node
    except Exception:  # noqa: BLE001
        return None


def build_link(node, idx):
    region = node.get("tag") or "XX"
    name = f"CF-{region}-{idx + 1:02d}"
    return (
        f"vless://{UUID}@{node['ip']}:{node['port']}"
        f"?encryption=none&security=tls&type=ws"
        f"&host={TARGET_HOST}&path={TARGET_PATH.replace('/', '%2F')}"
        f"&sni={TARGET_HOST}&fp=chrome#{name}"
    )


def bucket_seed():
    return int(time.time() // (6 * 3600))


def stable_hash(s, seed):
    return int(hashlib.sha256(f"{seed}:{s}".encode()).hexdigest()[:8], 16)


def main():
    log("=== CFNB 云端订阅生成 ===")
    pool, seen = [], set()
    for url in SOURCES:
        text, err = fetch(url)
        if err:
            log(f"[源失败] {url} -> {err}")
            continue
        items = parse_all(text)
        fresh = 0
        for it in items:
            key = f"{it['ip']}:{it['port']}"
            if key in seen:
                continue
            seen.add(key)
            it["cf"] = is_cf_ip(it["ip"])
            pool.append(it)
            fresh += 1
        log(f"[源成功] {url} -> 新增 {fresh} 条")

    if not pool:
        log("FATAL: 所有源均失败，保留旧订阅")
        return 2

    cf_pool = [n for n in pool if n["cf"]]
    other_pool = [n for n in pool if not n["cf"]]
    log(f"去重后候选 {len(pool)}（CF 官方段 {len(cf_pool)} / 第三方 {len(other_pool)}）")

    seed = bucket_seed()
    cf_pool.sort(key=lambda n: stable_hash(n["ip"], seed))
    other_pool.sort(key=lambda n: stable_hash(n["ip"], seed))

    # 端口 443 优先
    def pref(lst):
        return sorted(lst, key=lambda n: 0 if n["port"] == PREFERRED_PORT else 1)

    # 候选池：CF 官方段 40% + 第三方 60%，共 MAX_CANDIDATES 参与探测
    cf_n = min(max(int(MAX_CANDIDATES * 0.4), 20), len(cf_pool))
    ot_n = min(MAX_CANDIDATES - cf_n, len(other_pool))
    candidates = pref(cf_pool)[:cf_n] + pref(other_pool)[:ot_n]
    log(f"进入可用性探测：{len(candidates)} 个")

    alive = []
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        futures = {ex.submit(probe, n): n for n in candidates}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                alive.append(r)
    log(f"探测通过：{len(alive)} / {len(candidates)}")

    if not alive:
        log("FATAL: 无节点通过可用性探测，保留旧订阅")
        return 2

    # 延迟上限：剔除握手极慢的节点（>2500ms 体验极差）
    fast_enough = [n for n in alive if n["latency"] <= 2500]
    if len(fast_enough) >= 10:
        dropped = len(alive) - len(fast_enough)
        alive = fast_enough
        log(f"延迟过滤：保留 <=2500ms 的 {len(alive)} 个（剔除 {dropped} 个慢节点）")
    else:
        log(f"延迟过滤跳过：<=2500ms 仅 {len(fast_enough)} 个，放宽标准")

    alive.sort(key=lambda n: n["latency"])

    # 采样策略：限制同一 /16 网段数量，避免某一整段在国内不可达时批量失效；
    # 同时优先选用 Cloudflare 官方段（国内可达性显著优于第三方中转段）。
    MAX_PER_NET = 2
    CF_QUOTA = int(NODE_COUNT * 0.65)
    picked = []
    net_count = {}

    def fill(pool, stop_at):
        for n in pool:
            if len(picked) >= stop_at:
                return
            key = ".".join(n["ip"].split(".")[:2])
            if net_count.get(key, 0) >= MAX_PER_NET:
                continue
            if n in picked:
                continue
            net_count[key] = net_count.get(key, 0) + 1
            picked.append(n)

    cf_alive = [n for n in alive if n["cf"]]
    other_alive = [n for n in alive if not n["cf"]]
    fill(cf_alive, CF_QUOTA)
    fill(other_alive, NODE_COUNT)

    # 仍不足时放宽网段约束补齐
    if len(picked) < NODE_COUNT:
        for n in alive:
            if len(picked) >= NODE_COUNT:
                break
            if n not in picked:
                picked.append(n)

    log(f"网段分布：{len(net_count)} 个 /16，单段最多 {MAX_PER_NET} 个；CF 官方段 {sum(1 for n in picked if n['cf'])} 个")

    links = [build_link(n, i) for i, n in enumerate(picked)]
    body = "\n".join(links) + "\n"

    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)

    # 同时输出 base64 版本：部分客户端（含旧版 Karing 订阅导入）偏好 base64 编码
    b64_path = os.path.join(os.path.dirname(os.path.abspath(OUTPUT)) if os.path.dirname(OUTPUT) else ".",
                            "sub_final_b64.txt")
    with open(b64_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(base64.b64encode(body.encode("utf-8")).decode("ascii"))

    log(f"已写入 {OUTPUT}：{len(links)} 个节点")
    log(f"已写入 {b64_path}：base64 版本")
    log(f"延迟区间：{alive[0]['latency']}ms ~ {alive[-1]['latency']}ms")
    for n in picked[:5]:
        log(f"  示例 {n['ip']}:{n['port']} {n['latency']}ms status={n['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
