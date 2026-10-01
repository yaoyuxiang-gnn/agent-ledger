"""Render the GitHub social preview card from the real demo output.

Linked repos are judged before they are read: the 1280x640 card is what Slack,
X, LinkedIn, Discord and Hacker News show when somebody pastes the URL. It is
also the one image that no test can check, which is exactly why it is generated
rather than drawn — the transcript in it is captured from ``al demo``, so the
card cannot advertise output the software no longer prints.

Geometry is computed instead of hand-placed. The first draft of this card was
laid out by eye and shipped text that ran past the panel and a caption the pills
sat on top of; the layout is now derived from the measured line count, so
editing the copy cannot silently overflow anything.

Run it after any change to the demo:

    python tools/make_social_preview.py

Then upload ``.github/social-preview.png`` under
Settings -> General -> Social preview. GitHub has no API for that field.
"""

from __future__ import annotations

import io
import pathlib
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / ".github" / "social-preview.png"

WIDTH, HEIGHT = 1280, 640
SCALE = 2  # render large, downsample once: cheaper than antialiasing every glyph

BG_TOP = (13, 17, 23)
BG_BOTTOM = (9, 12, 17)
PANEL = (22, 27, 34)
PANEL_EDGE = (48, 54, 61)
INK = (230, 237, 243)
MUTED = (139, 148, 158)
DIM = (110, 118, 129)
ACCENT = (57, 197, 187)
GREEN = (63, 185, 80)
BLUE = (88, 166, 255)
RED = (248, 81, 73)
YELLOW = (210, 168, 255)

FONTS = {
    "mono": "C:/Windows/Fonts/consola.ttf",
    "mono_bold": "C:/Windows/Fonts/consolab.ttf",
    "ui": "C:/Windows/Fonts/segoeui.ttf",
    "ui_semibold": "C:/Windows/Fonts/seguisb.ttf",
}

#: Consolas has no box-drawing glyphs, so Pillow silently substitutes a font that
#: does and the tree comes out as ``\- legal-review``. The card is a rendering,
#: not a transcript: the *values* must be verbatim, the tree characters need only
#: read correctly, so they are normalised to ASCII.
TREE = {"├─": "|-", "└─": "`-", "│": "|", "▎": "|"}

#: Section headers, in both spellings the demo can produce. It draws ``▎`` when
#: the console encoding can carry it and falls back to ``|`` when it cannot —
#: which is why the first version of this script, looking only for ``▎``, ran
#: straight past the end of the block and tried to fit 25 lines into the panel.
SECTION_MARKERS = ("▎", "|")

#: Fixed layout, in final-image pixels. Anything dependent on the number of
#: demo lines is derived from `line_height` below.
#:
#: The sizes are set for the size this card is actually seen at: a Slack or X
#: timeline renders it around 500px wide, so the headline has to survive being
#: halved and the transcript has to survive being *quartered*. The first pass
#: used 21px monospace, which was legible on a 1280px canvas and unreadable in
#: the only place the card is ever displayed.
MARGIN = 64
RULE_TOP, RULE_BOTTOM = 56, 92
TITLE_SIZE = 34
TITLE_BASELINE = 50
HEAD_SIZE = 34
HEAD_LINES = ((110, "Who authorised this AI agent —"), (150, "and who answers for the result?"))
SUB_SIZE = 21
SUB_BASELINE = 186
PANEL_TOP = 212
LINE_HEIGHT = 38
PANEL_PAD_TOP = 46
PANEL_PAD_BOTTOM = 20
TERM_SIZE = 25
PILL_HEIGHT = 32
PILL_BOTTOM_GAP = 24
PILL_SIZE = 18


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    path = pathlib.Path(FONTS[name])
    if not path.exists():
        raise SystemExit(f"missing font {path}; adjust FONTS for this machine")
    return ImageFont.truetype(str(path), size * SCALE)


def capture_demo() -> list[str]:
    """Run the real demo and return its output lines.

    Called in-process with ``src`` on the path, the same way
    ``tools/check_readme.py`` reaches the CLI, so this works from a fresh clone
    with nothing installed.
    """
    from agent_ledger.cli import main

    buffer = io.StringIO()
    stdout, sys.stdout = sys.stdout, buffer
    try:
        code = main(["demo", "--no-color"])
    finally:
        sys.stdout = stdout
    if code != 0:
        raise SystemExit(f"al demo exited {code}; refusing to draw a card for a broken demo")
    return buffer.getvalue().splitlines()


def extract_chain(lines: list[str]) -> list[str]:
    """The 'Settling up' block: three hops, cost, and who is answerable."""
    start = next((i for i, line in enumerate(lines) if "Settling up" in line), None)
    if start is None:
        raise SystemExit("could not find the 'Settling up' section in the demo output")

    block: list[str] = []
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if stripped[:1] in SECTION_MARKERS:
            break
        if stripped:
            for drawn, ascii_form in TREE.items():
                line = line.replace(drawn, ascii_form)
            block.append(line.rstrip())
    if not 6 <= len(block) <= 12:
        raise SystemExit(
            f"the 'Settling up' section has {len(block)} lines, which is not the "
            f"shape this card was laid out for: {block!r}"
        )
    return block


def gradient(width: int, height: int) -> Image.Image:
    image = Image.new("RGB", (1, height))
    for y in range(height):
        t = y / max(height - 1, 1)
        image.putpixel(
            (0, y),
            tuple(round(a + (b - a) * t) for a, b in zip(BG_TOP, BG_BOTTOM, strict=True)),
        )
    return image.resize((width, height))


def rounded(draw: ImageDraw.ImageDraw, box, radius: int, fill, outline=None, width: int = 1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def chain_row(draw: ImageDraw.ImageDraw, line: str, x: int, y: int, f) -> None:
    """Colour one indented hop: tree, name, state, cost, receipt id."""
    parts = line.split()
    if len(parts) < 5:
        draw.text((x, y), line, font=f, fill=MUTED)
        return

    name_end = line.index(parts[1])
    prefix = line[:name_end]
    body = line[name_end:]
    state_at = body.index(parts[1]) + len(parts[1])
    name, rest = body[:state_at], body[state_at:]
    cost_at = rest.index("$")
    state, tail = rest[:cost_at], rest[cost_at:]
    receipt_at = tail.index("rcpt_")
    cost, receipt = tail[:receipt_at], tail[receipt_at:]

    cursor = x
    for text, fill, face in (
        (prefix, DIM, f),
        (name, MUTED, f),
        (state, BLUE, f),
        (cost, INK, f),
        (receipt, DIM, f),
    ):
        draw.text((cursor, y), text, font=face, fill=fill)
        cursor += draw.textlength(text, font=face)


def main() -> int:
    lines = capture_demo()
    chain = extract_chain(lines)

    canvas = gradient(WIDTH * SCALE, HEIGHT * SCALE)
    draw = ImageDraw.Draw(canvas)

    f_title = font("mono_bold", TITLE_SIZE)
    f_head = font("ui_semibold", HEAD_SIZE)
    f_sub = font("ui", SUB_SIZE)
    f_term = font("mono", TERM_SIZE)
    f_term_bold = font("mono_bold", TERM_SIZE)
    f_pill = font("mono", PILL_SIZE)

    left = MARGIN * SCALE
    right = (WIDTH - MARGIN) * SCALE
    text_x = left + 28 * SCALE

    # Panel height follows the transcript, so a longer demo makes a taller panel
    # rather than text spilling past its edge.
    panel_bottom = (
        (PANEL_TOP + PANEL_PAD_TOP) * SCALE + len(chain) * LINE_HEIGHT * SCALE
    ) + PANEL_PAD_BOTTOM * SCALE
    pill_top = panel_bottom // SCALE + PILL_BOTTOM_GAP
    bottom_edge = pill_top + PILL_HEIGHT

    draw.rectangle([left, RULE_TOP * SCALE, left + 7 * SCALE, RULE_BOTTOM * SCALE], fill=ACCENT)
    draw.text((left + 22 * SCALE, TITLE_BASELINE * SCALE), "agent-ledger", font=f_title, fill=INK)

    for baseline, text in HEAD_LINES:
        draw.text((left, baseline * SCALE), text, font=f_head, fill=INK)

    draw.text(
        (left, SUB_BASELINE * SCALE),
        "An append-only, signed ledger for agent delegations.",
        font=f_sub,
        fill=MUTED,
    )

    rounded(
        draw,
        [left, PANEL_TOP * SCALE, right, panel_bottom],
        radius=14 * SCALE,
        fill=PANEL,
        outline=PANEL_EDGE,
        width=SCALE,
    )

    dot_x = left + 26 * SCALE
    for i, colour in enumerate((RED, YELLOW, GREEN)):
        cx, cy = dot_x + i * 22 * SCALE, (PANEL_TOP + 25) * SCALE
        draw.ellipse([cx - 6 * SCALE, cy - 6 * SCALE, cx + 6 * SCALE, cy + 6 * SCALE], fill=colour)
    draw.text(
        (left + 108 * SCALE, (PANEL_TOP + 15) * SCALE), "$ al demo", font=f_term_bold, fill=DIM
    )

    y = (PANEL_TOP + PANEL_PAD_TOP) * SCALE
    for line in chain:
        stripped = line.strip()
        if stripped.startswith(("program-coordinator", "`-", "|-", "└─")):
            chain_row(draw, line, text_x, y, f_term)
        elif stripped.startswith("answerable to"):
            label = line[: line.index("urn:")] if "urn:" in line else line[: line.index("to") + 2]
            draw.text((text_x, y), label, font=f_term_bold, fill=ACCENT)
            draw.text(
                (text_x + draw.textlength(label, font=f_term_bold), y),
                line[len(label) :],
                font=f_term,
                fill=INK,
            )
        elif stripped.startswith(("chain length", "total cost")):
            label = line[: line.index(stripped.split()[2])]
            draw.text((text_x, y), label, font=f_term, fill=DIM)
            draw.text(
                (text_x + draw.textlength(label, font=f_term), y),
                line[len(label) :],
                font=f_term_bold,
                fill=INK,
            )
        elif stripped.startswith("violations"):
            label = line[: line.index("none")]
            draw.text((text_x, y), label, font=f_term, fill=DIM)
            draw.text(
                (text_x + draw.textlength(label, font=f_term), y),
                "none",
                font=f_term_bold,
                fill=GREEN,
            )
        else:
            draw.text((text_x, y), line, font=f_term, fill=MUTED)
        y += LINE_HEIGHT * SCALE

    # Three claims a reader can check in the next ten seconds, with the project's
    # own state beside them.
    pills = ("offline demo", "zero dependencies", "no API key")
    px = left
    for label in pills:
        box_right = px + draw.textlength(label, font=f_pill) + 34 * SCALE
        rounded(
            draw,
            [px, pill_top * SCALE, box_right, (pill_top + PILL_HEIGHT) * SCALE],
            radius=16 * SCALE,
            fill=PANEL,
            outline=PANEL_EDGE,
            width=SCALE,
        )
        draw.text(
            (px + 17 * SCALE, (pill_top + 7) * SCALE),
            label,
            font=f_pill,
            fill=ACCENT,
        )
        px = box_right + 14 * SCALE

    if bottom_edge > HEIGHT:
        raise SystemExit(
            f"layout overflows the card by {bottom_edge - HEIGHT}px "
            f"({len(chain)} transcript lines, line height {LINE_HEIGHT}); "
            "lower LINE_HEIGHT or shorten the captured block"
        )

    card = canvas.resize((WIDTH, HEIGHT), Image.LANCZOS)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    card.save(OUT, format="PNG", optimize=True)

    size_kb = OUT.stat().st_size / 1024
    print(f"wrote {OUT.relative_to(ROOT)}  {WIDTH}x{HEIGHT}  {size_kb:.0f} KB")
    print(
        f"  transcript lines: {len(chain)}  panel {PANEL_TOP}-{panel_bottom // SCALE}  "
        f"pills at {pill_top}  bottom edge {bottom_edge}/{HEIGHT}"
    )
    if size_kb > 1024:
        print("WARNING: GitHub's limit is 1 MB for a social preview image")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
