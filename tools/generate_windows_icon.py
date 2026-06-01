from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image


SIZES = [16, 32, 48, 64, 128]


def build_dib(image: Image.Image, size: int) -> bytes:
    frame = image.resize((size, size), Image.Resampling.LANCZOS).convert("RGBA")
    xor_rows: list[bytes] = []
    and_rows: list[bytes] = []

    mask_stride = ((size + 31) // 32) * 4
    for y in range(size - 1, -1, -1):
        xor_row = bytearray()
        and_row = bytearray(mask_stride)
        for x in range(size):
            r, g, b, a = frame.getpixel((x, y))
            xor_row.extend((b, g, r, a))
            if a < 128:
                and_row[x // 8] |= 0x80 >> (x % 8)
        xor_rows.append(bytes(xor_row))
        and_rows.append(bytes(and_row))

    bitmap_info_header = struct.pack(
        "<IIIHHIIIIII",
        40,
        size,
        size * 2,
        1,
        32,
        0,
        size * size * 4,
        0,
        0,
        0,
        0,
    )
    return bitmap_info_header + b"".join(xor_rows) + b"".join(and_rows)


def build_ico(source: Path, destinations: list[Path]) -> None:
    image = Image.open(source).convert("RGBA")
    payloads = [build_dib(image, size) for size in SIZES]
    header = struct.pack("<HHH", 0, 1, len(SIZES))

    directory = bytearray()
    offset = 6 + 16 * len(SIZES)
    for size, payload in zip(SIZES, payloads, strict=True):
        directory.extend(
            struct.pack(
                "<BBBBHHII",
                0 if size == 256 else size,
                0 if size == 256 else size,
                0,
                0,
                1,
                32,
                len(payload),
                offset,
            )
        )
        offset += len(payload)

    output = header + bytes(directory) + b"".join(payloads)
    for destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(output)
        print(f"wrote {destination}")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "src-tauri" / "icons" / "icon.png"
    destinations = [
        root / "src-tauri" / "icons" / "icon.ico",
        root / "rss.ico",
    ]
    build_ico(source, destinations)


if __name__ == "__main__":
    main()
