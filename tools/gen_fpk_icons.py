#!/usr/bin/env python3
"""生成 fnOS 应用图标（纯标准库，不依赖 Pillow）。

图形语义：一块磁盘盘片（蓝色环）＋ 一道穿过它的心跳波形（琥珀色）。
盘片代表被监控的硬盘，波形代表「唤醒」这个动作。

输出（都必须是不透明 PNG）：
    ICON.PNG            64x64
    ICON_256.PNG        256x256
    app/ui/images/icon_64.png
    app/ui/images/icon_256.png
"""

from __future__ import annotations

import math
import os
import struct
import sys
import zlib

BG_TOP = (30, 44, 60)
BG_BOT = (10, 15, 21)
GLOW = (72, 122, 200)
RING = (47, 111, 235)
RING_INNER = (36, 56, 88)
PULSE = (255, 194, 75)

SS = 4  # 超采样倍数

# 心跳波形折线（归一化坐标）
WAVE = [
    (0.170, 0.500),
    (0.352, 0.500),
    (0.434, 0.332),
    (0.548, 0.668),
    (0.628, 0.500),
    (0.830, 0.500),
]


def _mix(a, b, t: float):
    t = max(0.0, min(1.0, t))
    return (
        a[0] + (b[0] - a[0]) * t,
        a[1] + (b[1] - a[1]) * t,
        a[2] + (b[2] - a[2]) * t,
    )


def _seg_dist(px, py, ax, ay, bx, by) -> float:
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    seg_len_sq = vx * vx + vy * vy
    if seg_len_sq <= 1e-12:
        return math.hypot(wx, wy)
    t = (wx * vx + wy * vy) / seg_len_sq
    t = 0.0 if t < 0.0 else (1.0 if t > 1.0 else t)
    return math.hypot(px - (ax + t * vx), py - (ay + t * vy))


def _wave_dist(px, py) -> float:
    best = 1e9
    for i in range(len(WAVE) - 1):
        ax, ay = WAVE[i]
        bx, by = WAVE[i + 1]
        d = _seg_dist(px, py, ax, ay, bx, by)
        if d < best:
            best = d
    return best


def _shade(px, py) -> tuple:
    """返回单点颜色（0-255 三元组）。px/py 为 0..1 归一化坐标。"""
    color = _mix(BG_TOP, BG_BOT, py)

    # 中心柔光，避免大面积死黑
    dist = math.hypot(px - 0.5, py - 0.5)
    glow = 0.20 * math.exp(-((dist / 0.42) ** 2))
    color = _mix(color, GLOW, glow)

    # 盘片内的细纹（第二圈），增加一点机械硬盘的层次
    if 0.196 <= dist <= 0.212:
        color = _mix(color, RING_INNER, 0.95)

    # 盘片主环
    if 0.232 <= dist <= 0.300:
        color = _mix(color, RING, 1.0)
        # 环上一点竖向渐变，让环有厚度感
        edge = min(dist - 0.232, 0.300 - dist) / 0.034
        color = _mix(color, (255, 255, 255), 0.10 * edge)

    # 心跳波形
    wave = _wave_dist(px, py)
    if wave <= 0.026:
        color = _mix(color, PULSE, 1.0)
    elif wave <= 0.034:
        color = _mix(color, PULSE, (0.034 - wave) / 0.008)

    return color


def render(size: int) -> bytes:
    """渲染为 RGBA 像素数据（返回原始字节，行序自上而下）。"""
    big = size * SS
    pixels = bytearray(size * size * 4)

    for y in range(size):
        for x in range(size):
            r = g = b = 0.0
            for sy in range(SS):
                py = (y * SS + sy + 0.5) / big
                for sx in range(SS):
                    px = (x * SS + sx + 0.5) / big
                    cr, cg, cb = _shade(px, py)
                    r += cr
                    g += cg
                    b += cb
            n = SS * SS
            idx = (y * size + x) * 4
            pixels[idx] = int(round(r / n))
            pixels[idx + 1] = int(round(g / n))
            pixels[idx + 2] = int(round(b / n))
            pixels[idx + 3] = 255  # 必须不透明

    return bytes(pixels)


def write_png(path: str, size: int, rgba: bytes) -> None:
    raw = bytearray()
    stride = size * 4
    for y in range(size):
        raw.append(0)  # filter type 0
        raw.extend(rgba[y * stride : (y + 1) * stride])

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(png)


def main(argv: list) -> int:
    out_dir = argv[1] if len(argv) > 1 else "."
    targets = [
        (64, os.path.join(out_dir, "ICON.PNG")),
        (256, os.path.join(out_dir, "ICON_256.PNG")),
        (64, os.path.join(out_dir, "app", "ui", "images", "icon_64.png")),
        (256, os.path.join(out_dir, "app", "ui", "images", "icon_256.png")),
    ]

    cache = {}
    for size, path in targets:
        if size not in cache:
            cache[size] = render(size)
            print("rendered %dx%d" % (size, size))
        write_png(path, size, cache[size])
        print("wrote %s" % path)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
