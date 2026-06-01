from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image


WINDOWS_ICON_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128)]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: build_windows_ico.py <source-png> <target-ico>", file=sys.stderr)
        return 1

    source = Path(sys.argv[1]).resolve()
    target = Path(sys.argv[2]).resolve()

    if not source.is_file():
        print(f"source png not found: {source}", file=sys.stderr)
        return 1

    target.parent.mkdir(parents=True, exist_ok=True)

    with Image.open(source) as image:
        image = image.convert("RGBA")
        image.save(
            target,
            format="ICO",
            sizes=WINDOWS_ICON_SIZES,
            bitmap_format="bmp",
        )

    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
