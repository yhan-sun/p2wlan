#!/usr/bin/env python3
"""Generate p2wlan app and tray icons.

The visual system is intentionally round and spare:
- app icons use a white rounded tile with transparent outer corners
- tray/taskbar icons use only the infinity mark on a transparent canvas
- small sizes are generated from a bolder tray source instead of shrinking the
  full app tile
"""

from __future__ import annotations

import math
import shutil
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter


ROOT = Path(__file__).resolve().parents[1]
FLUTTER_ROOT = ROOT / "apps" / "flutter_client"
FLUTTER_ASSETS = FLUTTER_ROOT / "assets"
MACOS_APPICON_DIR = (
    FLUTTER_ROOT / "macos" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset"
)
IOS_APPICON_DIR = (
    FLUTTER_ROOT / "ios" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset"
)
ANDROID_RES_DIR = FLUTTER_ROOT / "android" / "app" / "src" / "main" / "res"
WINDOWS_RES_DIR = FLUTTER_ROOT / "windows" / "runner" / "resources"

SOURCE_SIZE = 1024
SUPERSAMPLE = 4
BLUE = (70, 174, 235)
GREEN = (110, 225, 146)
MENU_WHITE = (246, 247, 249)
CONNECTED_GREEN = (46, 213, 126)
ATTENTION_RED = (248, 96, 116)


APP_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="tile" x1="82" y1="82" x2="430" y2="430" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#ffffff"/>
      <stop offset="0.46" stop-color="#f8fdff"/>
      <stop offset="1" stop-color="#f3fff6"/>
    </linearGradient>
    <linearGradient id="mark" x1="142" y1="256" x2="370" y2="256" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#46aeeb"/>
      <stop offset="1" stop-color="#6ee192"/>
    </linearGradient>
    <filter id="softShadow" x="-18%" y="-16%" width="136%" height="140%">
      <feDropShadow dx="0" dy="14" stdDeviation="13" flood-color="#1f2937" flood-opacity="0.16"/>
    </filter>
  </defs>
  <rect width="512" height="512" fill="none"/>
  <rect x="62" y="62" width="388" height="388" rx="92" fill="url(#tile)" filter="url(#softShadow)"/>
  <rect x="66" y="66" width="380" height="380" rx="88" fill="none" stroke="#e8edf0" stroke-width="3"/>
  <path
    d="M256 256
       C282 166 372 188 372 256
       C372 324 282 346 256 256
       C230 166 140 188 140 256
       C140 324 230 346 256 256"
    fill="none"
    stroke="url(#mark)"
    stroke-width="50"
    stroke-linecap="round"
    stroke-linejoin="round"/>
</svg>
"""


def ensure_dirs() -> None:
    for directory in [
        FLUTTER_ASSETS,
        MACOS_APPICON_DIR,
        IOS_APPICON_DIR,
        WINDOWS_RES_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)


def mix(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rounded_mask(size: int, box: tuple[int, int, int, int], radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle(box, radius=radius, fill=255)
    return mask


def alpha_from(image: Image.Image) -> Image.Image:
    return image.getchannel("A")


def offset_layer(layer: Image.Image, dx: int, dy: int) -> Image.Image:
    shifted = Image.new("RGBA", layer.size, (0, 0, 0, 0))
    shifted.alpha_composite(layer, (dx, dy))
    return shifted


def lemniscate_points(
    center: tuple[int, int],
    radius_x: int,
    radius_y: int,
    count: int = 680,
) -> list[tuple[int, int]]:
    cx, cy = center
    points: list[tuple[int, int]] = []
    # Start just past the center crossing so the rounded stroke cap is hidden by
    # the later crossing pass.
    for index in range(count + 1):
        t = (index / count) * math.tau + 0.022
        x = cx + radius_x * math.sin(t)
        y = cy + radius_y * math.sin(t) * math.cos(t)
        points.append((round(x), round(y)))
    return points


def gradient_image(
    size: int,
    start_color: tuple[int, int, int],
    end_color: tuple[int, int, int],
    alpha: int,
) -> Image.Image:
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    px = image.load()
    for x in range(size):
        color = mix(start_color, end_color, x / max(1, size - 1))
        for y in range(size):
            px[x, y] = (*color, alpha)
    return image


def path_mask(size: int, points: list[tuple[int, int]], width: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.line(points, fill=255, width=width, joint="curve")
    radius = width // 2
    for point in (points[0], points[-1]):
        draw.ellipse(
            (point[0] - radius, point[1] - radius, point[0] + radius, point[1] + radius),
            fill=255,
        )
    return mask


def draw_gradient_path(
    layer: Image.Image,
    points: list[tuple[int, int]],
    width: int,
    start_color: tuple[int, int, int],
    end_color: tuple[int, int, int],
    alpha: int = 255,
) -> None:
    mask = path_mask(layer.size[0], points, width)
    gradient = gradient_image(layer.size[0], start_color, end_color, alpha)
    gradient.putalpha(mask.point(lambda value: round(value * (alpha / 255))))
    layer.alpha_composite(gradient)


def make_mark_layer(
    size: int,
    *,
    center: tuple[int, int],
    radius_x: int,
    radius_y: int,
    width: int,
    start_color: tuple[int, int, int] = BLUE,
    end_color: tuple[int, int, int] = GREEN,
) -> Image.Image:
    mark = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    points = lemniscate_points(center, radius_x, radius_y)

    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw_gradient_path(glow, points, round(width * 1.24), start_color, end_color, 96)
    glow = glow.filter(ImageFilter.GaussianBlur(max(4, width // 8)))
    mark.alpha_composite(glow)

    draw_gradient_path(mark, points, width, start_color, end_color)

    highlight = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw_gradient_path(highlight, points, max(2, round(width * 0.32)), (255, 255, 255), (255, 255, 255), 70)
    highlight_mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(highlight_mask).rectangle((0, 0, size, center[1] - width // 5), fill=255)
    highlight.putalpha(Image.composite(alpha_from(highlight), Image.new("L", (size, size), 0), highlight_mask))
    mark.alpha_composite(highlight)

    return mark


def downsample(image: Image.Image, target_size: int) -> Image.Image:
    return image.resize((target_size, target_size), Image.Resampling.LANCZOS)


def make_app_icon(size: int = SOURCE_SIZE) -> Image.Image:
    canvas_size = size * SUPERSAMPLE
    scale = canvas_size / SOURCE_SIZE

    def u(value: float) -> int:
        return round(value * scale)

    canvas = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    tile_box = (u(110), u(110), u(914), u(914))
    tile_radius = u(198)

    shadow = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow)
    shadow_draw.rounded_rectangle(
        (tile_box[0], tile_box[1] + u(20), tile_box[2], tile_box[3] + u(20)),
        radius=tile_radius,
        fill=(20, 28, 44, 68),
    )
    shadow = shadow.filter(ImageFilter.GaussianBlur(u(30)))
    canvas.alpha_composite(shadow)

    tile = Image.new("RGBA", canvas.size, (255, 255, 255, 0))
    tile_draw = ImageDraw.Draw(tile)
    tile_draw.rounded_rectangle(tile_box, radius=tile_radius, fill=(255, 255, 255, 255))

    wash = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    wash_draw = ImageDraw.Draw(wash)
    wash_draw.ellipse((u(-170), u(180), u(650), u(930)), fill=(69, 174, 235, 42))
    wash_draw.ellipse((u(360), u(85), u(1120), u(925)), fill=(112, 225, 146, 44))
    wash = wash.filter(ImageFilter.GaussianBlur(u(95)))
    tile.alpha_composite(wash)

    mask = rounded_mask(canvas_size, tile_box, tile_radius)
    clipped_tile = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    clipped_tile = Image.composite(tile, clipped_tile, mask)
    canvas.alpha_composite(clipped_tile)

    border = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    border_draw = ImageDraw.Draw(border)
    border_draw.rounded_rectangle(
        (u(114), u(114), u(910), u(910)),
        radius=u(194),
        outline=(226, 233, 237, 190),
        width=u(5),
    )
    border_draw.rounded_rectangle(
        (u(142), u(142), u(882), u(882)),
        radius=u(172),
        outline=(255, 255, 255, 185),
        width=u(3),
    )
    canvas.alpha_composite(border)

    mark = make_mark_layer(
        canvas_size,
        center=(u(512), u(528)),
        radius_x=u(226),
        radius_y=u(162),
        width=u(100),
    )
    mark_shadow = Image.new("RGBA", canvas.size, (25, 44, 55, 0))
    mark_shadow.putalpha(alpha_from(mark).point(lambda value: round(value * 0.18)))
    mark_shadow = offset_layer(mark_shadow.filter(ImageFilter.GaussianBlur(u(10))), 0, u(11))
    canvas.alpha_composite(mark_shadow)
    canvas.alpha_composite(mark)

    return downsample(canvas, size)


def make_tray_icon(
    size: int = 256,
    *,
    start_color: tuple[int, int, int] = BLUE,
    end_color: tuple[int, int, int] = GREEN,
    badge_color: tuple[int, int, int] | None = None,
    slash: bool = False,
) -> Image.Image:
    canvas_size = size * SUPERSAMPLE
    scale = canvas_size / 256

    def u(value: float) -> int:
        return round(value * scale)

    mark = make_mark_layer(
        canvas_size,
        center=(u(124), u(128)),
        radius_x=u(92),
        radius_y=u(66),
        width=u(44),
        start_color=start_color,
        end_color=end_color,
    )
    draw = ImageDraw.Draw(mark)
    if slash:
        draw.line((u(34), u(50), u(204), u(210)), fill=(255, 255, 255, 230), width=u(19))
        draw.line((u(40), u(56), u(198), u(204)), fill=(*MENU_WHITE, 255), width=u(12))
    if badge_color is not None:
        cx, cy = u(218), u(190)
        outer = u(23)
        inner = u(16)
        draw.ellipse((cx - outer, cy - outer, cx + outer, cy + outer), fill=(255, 255, 255, 245))
        draw.ellipse((cx - inner, cy - inner, cx + inner, cy + inner), fill=(*badge_color, 255))
    return downsample(mark, size)


def flatten_on_white(image: Image.Image) -> Image.Image:
    flattened = Image.new("RGB", image.size, (255, 255, 255))
    flattened.paste(image, mask=image.getchannel("A"))
    return flattened


def save_resized(source: Image.Image, path: Path, size: int, *, opaque: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image = source.resize((size, size), Image.Resampling.LANCZOS)
    if opaque:
        image = flatten_on_white(image)
    image.save(path)


def generate_icns(source: Image.Image, path: Path) -> None:
    iconset = path.with_suffix(".iconset")
    if iconset.exists():
        shutil.rmtree(iconset)
    iconset.mkdir(parents=True)
    for size in [16, 32, 128, 256, 512]:
        save_resized(source, iconset / f"icon_{size}x{size}.png", size)
        save_resized(source, iconset / f"icon_{size}x{size}@2x.png", size * 2)
    subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(path)], check=True)
    shutil.rmtree(iconset)


def generate_ico(source: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    source.save(path, sizes=sizes)


def write_svg_assets() -> None:
    for path in [ROOT / "assets" / "p2wlan_icon.svg", FLUTTER_ASSETS / "p2wlan_icon.svg"]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(APP_ICON_SVG, encoding="utf-8")


def generate_flutter_icons(app_icon: Image.Image, tray_icon: Image.Image) -> None:
    save_resized(tray_icon, FLUTTER_ASSETS / "tray_icon.png", 64)
    generate_ico(tray_icon, FLUTTER_ASSETS / "tray_icon.ico")
    save_resized(
        make_tray_icon(
            256,
            start_color=MENU_WHITE,
            end_color=MENU_WHITE,
        ),
        FLUTTER_ASSETS / "tray_icon_macos_off.png",
        64,
    )
    save_resized(
        make_tray_icon(
            256,
            start_color=CONNECTED_GREEN,
            end_color=(76, 232, 166),
            badge_color=CONNECTED_GREEN,
        ),
        FLUTTER_ASSETS / "tray_icon_macos_on.png",
        64,
    )
    save_resized(
        make_tray_icon(
            256,
            start_color=MENU_WHITE,
            end_color=MENU_WHITE,
        ),
        FLUTTER_ASSETS / "tray_icon_macos_busy.png",
        64,
    )
    save_resized(
        make_tray_icon(
            256,
            start_color=ATTENTION_RED,
            end_color=(248, 113, 113),
            badge_color=ATTENTION_RED,
        ),
        FLUTTER_ASSETS / "tray_icon_macos_attention.png",
        64,
    )

    generate_ico(app_icon, WINDOWS_RES_DIR / "app_icon.ico")

    for size in [16, 32, 64, 128, 256, 512, 1024]:
        save_resized(app_icon, MACOS_APPICON_DIR / f"app_icon_{size}.png", size)

    ios_sizes = {
        "Icon-App-20x20@1x.png": 20,
        "Icon-App-20x20@2x.png": 40,
        "Icon-App-20x20@3x.png": 60,
        "Icon-App-29x29@1x.png": 29,
        "Icon-App-29x29@2x.png": 58,
        "Icon-App-29x29@3x.png": 87,
        "Icon-App-40x40@1x.png": 40,
        "Icon-App-40x40@2x.png": 80,
        "Icon-App-40x40@3x.png": 120,
        "Icon-App-60x60@2x.png": 120,
        "Icon-App-60x60@3x.png": 180,
        "Icon-App-76x76@1x.png": 76,
        "Icon-App-76x76@2x.png": 152,
        "Icon-App-83.5x83.5@2x.png": 167,
        "Icon-App-1024x1024@1x.png": 1024,
    }
    for filename, size in ios_sizes.items():
        # iOS app icons are expected to be opaque, so keep the same white visual
        # language while flattening the alpha channel for that platform only.
        save_resized(app_icon, IOS_APPICON_DIR / filename, size, opaque=True)

    android_sizes = {
        "mipmap-mdpi": 48,
        "mipmap-hdpi": 72,
        "mipmap-xhdpi": 96,
        "mipmap-xxhdpi": 144,
        "mipmap-xxxhdpi": 192,
    }
    for folder, size in android_sizes.items():
        save_resized(app_icon, ANDROID_RES_DIR / folder / "ic_launcher.png", size)


def make_preview(app_icon: Image.Image, tray_icon: Image.Image) -> Path:
    preview = Image.new("RGBA", (1220, 560), (250, 248, 244, 255))
    draw = ImageDraw.Draw(preview)
    draw.rounded_rectangle((38, 38, 1182, 522), radius=38, fill=(255, 255, 255, 246), outline=(232, 226, 218, 255), width=2)
    draw.text((96, 468), "App icon", fill=(104, 99, 92, 255))
    draw.text((648, 468), "Transparent tray/taskbar icons", fill=(104, 99, 92, 255))

    preview.alpha_composite(app_icon.resize((300, 300), Image.Resampling.LANCZOS), (102, 118))
    for index, size in enumerate([96, 64, 48, 32, 24, 16]):
        x = 542 + index * 105
        y = 210 + (96 - size) // 2
        draw.rounded_rectangle((x - 16, 178, x + 112, 306), radius=20, fill=(246, 248, 250, 255))
        preview.alpha_composite(tray_icon.resize((size, size), Image.Resampling.LANCZOS), (x + (96 - size) // 2, y))
        draw.text((x + 22, 328), f"{size}px", fill=(104, 99, 92, 255))

    out = ROOT / "tmp" / "icon-preview.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    preview.convert("RGB").save(out)
    return out


def main() -> None:
    ensure_dirs()
    write_svg_assets()

    app_icon = make_app_icon()
    tray_icon = make_tray_icon()
    generate_flutter_icons(app_icon, tray_icon)
    preview = make_preview(app_icon, tray_icon)

    print(f"Generated Flutter icons in {FLUTTER_ROOT}")
    print(f"Preview written to {preview}")


if __name__ == "__main__":
    main()
