#!/usr/bin/env python3
"""Generate p2wlan app icons for Tauri bundles.

The mark is intentionally simple at small sizes: three overlay nodes, a
central tunnel ring, and a restrained network-grid hint on a native rounded
app tile.
"""

from __future__ import annotations

import math
import shutil
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter


ROOT = Path(__file__).resolve().parents[1]
ICON_DIR = ROOT / "src-tauri" / "icons"
SOURCE_SIZE = 1024


def lerp(a: int, b: int, t: float) -> int:
    return round(a + (b - a) * t)


def gradient_tile(size: int) -> Image.Image:
    top = (10, 29, 43)
    bottom = (9, 72, 78)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    px = img.load()
    for y in range(size):
        for x in range(size):
            t = (y / (size - 1)) * 0.82 + (x / (size - 1)) * 0.18
            px[x, y] = (
                lerp(top[0], bottom[0], t),
                lerp(top[1], bottom[1], t),
                lerp(top[2], bottom[2], t),
                255,
            )
    return img


def rounded_mask(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return mask


def draw_glow(base: Image.Image, center: tuple[int, int], radius: int, color: tuple[int, int, int], alpha: int) -> None:
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    x, y = center
    draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=(*color, alpha))
    layer = layer.filter(ImageFilter.GaussianBlur(radius // 2))
    base.alpha_composite(layer)


def draw_line_with_glow(
    base: Image.Image,
    points: list[tuple[int, int]],
    color: tuple[int, int, int],
    width: int,
) -> None:
    glow = Image.new("RGBA", base.size, (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    glow_draw.line(points, fill=(*color, 95), width=width + 22, joint="curve")
    glow = glow.filter(ImageFilter.GaussianBlur(18))
    base.alpha_composite(glow)

    draw = ImageDraw.Draw(base)
    draw.line(points, fill=(*color, 215), width=width, joint="curve")


def make_icon() -> Image.Image:
    size = SOURCE_SIZE
    icon = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    shadow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow)
    shadow_draw.rounded_rectangle((84, 96, 940, 952), radius=214, fill=(0, 0, 0, 120))
    shadow = shadow.filter(ImageFilter.GaussianBlur(34))
    icon.alpha_composite(shadow)

    tile = gradient_tile(size)
    mask = rounded_mask(size, 210)
    icon = Image.composite(tile, icon, mask)

    draw = ImageDraw.Draw(icon)
    draw.rounded_rectangle((78, 78, 946, 946), radius=210, outline=(135, 231, 236, 36), width=6)
    draw.rounded_rectangle((106, 106, 918, 918), radius=188, outline=(255, 255, 255, 22), width=3)

    # Quiet grid: enough to suggest LAN, faint enough not to clutter small icons.
    for offset in range(-512, 1024, 128):
        draw.line((offset, 780, offset + 780, 0), fill=(129, 219, 224, 26), width=2)
        draw.line((offset, 1024, offset + 1024, 0), fill=(28, 121, 132, 34), width=2)

    draw_glow(icon, (520, 470), 310, (34, 211, 211), 80)
    draw_glow(icon, (722, 706), 210, (87, 229, 154), 72)

    teal = (81, 229, 232)
    green = (98, 236, 164)
    white = (233, 253, 255)

    nodes = {
        "top": (512, 265),
        "left": (294, 660),
        "right": (730, 660),
    }
    draw_line_with_glow(icon, [nodes["top"], nodes["left"]], teal, 36)
    draw_line_with_glow(icon, [nodes["top"], nodes["right"]], teal, 36)
    draw_line_with_glow(icon, [nodes["left"], nodes["right"]], green, 32)

    # Central tunnel ring.
    ring_box = (348, 392, 676, 720)
    ring_glow = Image.new("RGBA", icon.size, (0, 0, 0, 0))
    ring_draw = ImageDraw.Draw(ring_glow)
    ring_draw.ellipse(ring_box, outline=(94, 235, 237, 150), width=62)
    ring_glow = ring_glow.filter(ImageFilter.GaussianBlur(20))
    icon.alpha_composite(ring_glow)
    draw.ellipse(ring_box, outline=(232, 254, 255, 236), width=42)
    draw.ellipse((418, 462, 606, 650), outline=(78, 230, 236, 190), width=22)
    draw.arc((366, 410, 658, 702), start=306, end=44, fill=(98, 236, 164, 255), width=52)

    for name, (x, y) in nodes.items():
        radius = 78 if name == "top" else 72
        node_shadow = Image.new("RGBA", icon.size, (0, 0, 0, 0))
        sd = ImageDraw.Draw(node_shadow)
        sd.ellipse((x - radius, y - radius + 12, x + radius, y + radius + 12), fill=(0, 0, 0, 115))
        node_shadow = node_shadow.filter(ImageFilter.GaussianBlur(18))
        icon.alpha_composite(node_shadow)

        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=(7, 32, 44, 255))
        draw.ellipse((x - radius + 10, y - radius + 10, x + radius - 10, y + radius - 10), fill=(17, 128, 138, 255))
        draw.ellipse((x - radius + 24, y - radius + 24, x + radius - 24, y + radius - 24), fill=(*white, 255))
        draw.ellipse((x - 19, y - 19, x + 19, y + 19), fill=((*green, 255) if name == "right" else (*teal, 255)))

    # Bottom cut suggests an underlay route, not text.
    draw.rounded_rectangle((398, 790, 626, 838), radius=24, fill=(232, 254, 255, 220))
    draw.rounded_rectangle((454, 806, 570, 822), radius=8, fill=(13, 78, 86, 230))

    return icon


def save_resized(source: Image.Image, path: Path, size: int) -> None:
    img = source.resize((size, size), Image.Resampling.LANCZOS)
    img.save(path)


def generate_icns(source: Image.Image) -> None:
    iconset = ICON_DIR / "icon.iconset"
    if iconset.exists():
        shutil.rmtree(iconset)
    iconset.mkdir(parents=True)
    sizes = [16, 32, 128, 256, 512]
    for size in sizes:
        save_resized(source, iconset / f"icon_{size}x{size}.png", size)
        save_resized(source, iconset / f"icon_{size}x{size}@2x.png", size * 2)
    subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(ICON_DIR / "icon.icns")], check=True)
    shutil.rmtree(iconset)


def generate_ico(source: Image.Image) -> None:
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    source.save(ICON_DIR / "icon.ico", sizes=sizes)


def main() -> None:
    ICON_DIR.mkdir(parents=True, exist_ok=True)
    source = make_icon()
    source.save(ICON_DIR / "icon-source.png")
    save_resized(source, ICON_DIR / "icon.png", 512)
    save_resized(source, ICON_DIR / "32x32.png", 32)
    save_resized(source, ICON_DIR / "128x128.png", 128)
    save_resized(source, ICON_DIR / "128x128@2x.png", 256)

    for size in [30, 44, 71, 89, 107, 142, 150, 284, 310]:
        save_resized(source, ICON_DIR / f"Square{size}x{size}Logo.png", size)
    save_resized(source, ICON_DIR / "StoreLogo.png", 50)
    generate_icns(source)
    generate_ico(source)
    print(f"Generated icons in {ICON_DIR}")


if __name__ == "__main__":
    main()
