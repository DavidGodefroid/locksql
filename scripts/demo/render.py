#!/usr/bin/env python3
"""Renders a rec.py recording (tmux screens with SGR colours) to PNG frames + an ffmpeg concat list."""
import json, re, sys, os, hashlib
from PIL import Image, ImageDraw, ImageFont
src, outdir = sys.argv[1], sys.argv[2]
T0 = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0      # start of the kept span (s)
T1 = float(sys.argv[4]) if len(sys.argv) > 4 else 1e9
os.makedirs(outdir, exist_ok=True)
CW, CH, FS = 9.7, 21, 16
COLS = (79, 92); ROWS = 42
PAD, TITLE = 16, 34
W = int(round(PAD * 2 + (COLS[0] + 1 + COLS[1]) * CW)); H = TITLE + ROWS * CH + PAD + 8
W += W % 2; H += H % 2
BG, FG = (0x1a, 0x18, 0x14), (0xe6, 0xe1, 0xd6)
PAL = [(0x3a,0x36,0x2e),(0xff,0x93,0x84),(0x7f,0xcf,0x8a),(0xe8,0xb8,0x60),(0x89,0xb4,0xfa),(0xc4,0xa7,0xe7),(0x6f,0xd9,0xc8),(0xd8,0xd2,0xc4),
       (0x7a,0x73,0x64),(0xff,0xa8,0x9c),(0x9c,0xe0,0xa5),(0xf2,0xcd,0x85),(0xa3,0xbd,0xff),(0xd6,0xbf,0xf2),(0x8f,0xe8,0xd9),(0xf4,0xef,0xe4)]
def c256(n):
    if n < 16: return PAL[n]
    if n < 232:
        n -= 16; v = [0, 95, 135, 175, 215, 255]; return (v[n // 36], v[n // 6 % 6], v[n % 6])
    g = 8 + (n - 232) * 10; return (g, g, g)
D = "/usr/share/fonts/truetype/dejavu/"
F = {(0, 0): ImageFont.truetype(D + "DejaVuSansMono.ttf", FS), (1, 0): ImageFont.truetype(D + "DejaVuSansMono-Bold.ttf", FS),
     (0, 1): ImageFont.truetype(D + "DejaVuSansMono-Oblique.ttf", FS), (1, 1): ImageFont.truetype(D + "DejaVuSansMono-BoldOblique.ttf", FS)}
N = "/usr/share/fonts/truetype/"
FALL = [ImageFont.truetype(N + p, FS) for p in ("noto/NotoSansSymbols2-Regular.ttf", "noto/NotoSansSymbols-Regular.ttf", "freefont/FreeMono.ttf")]
EMO = ImageFont.truetype(N + "noto/NotoColorEmoji.ttf", 109)
_ec = {}
def emoji(ch):
    if ch not in _ec:
        im = Image.new("RGBA", (136, 128), (0, 0, 0, 0)); ImageDraw.Draw(im).text((0, 0), ch, font=EMO, embedded_color=True)
        _ec[ch] = im.resize((17, 16), Image.LANCZOS)
    return _ec[ch]
SCRUB = (re.compile(r"(?<=Sonnet \d\.\d) · Claude \w+"), re.compile(r" · ← \d+ agents?"))   # the recording account's plan and session count, blanked
HIDE = ("Your login expires", "tmux focus-events off")   # notices of the recording machine (account, tmux tip), blanked
UI = ImageFont.truetype(D + "DejaVuSansMono.ttf", 14)
_hc = {}
def _bits(font, ch):
    im = Image.new("L", (40, 40), 0); ImageDraw.Draw(im).text((4, 4), ch, font=font, fill=255); return im.tobytes()
def has(font, ch):
    k = (id(font), ch)
    if k not in _hc: _hc[k] = _bits(font, ch) not in (_bits(font, "\U000fffff"), _bits(font, " "))
    return _hc[k]
SGR = re.compile(r"\x1b\[([0-9;:]*)m|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[A-Za-z]|[\x0e\x0f]")
def parse(text):
    rows = []
    st = dict(fg=None, bg=None, b=0, d=0, i=0, u=0, r=0)
    for line in text.split("\n")[:ROWS]:
        if any(h in line for h in HIDE): line = ""
        cells = []; pos = 0
        for m in SGR.finditer(line):
            for ch in line[pos:m.start()]: cells.append((ch, dict(st)))
            pos = m.end()
            if m.group(1) is None: continue
            ps = [int(x) if x else 0 for x in re.split("[;:]", m.group(1))] if m.group(1) else [0]
            k = 0
            while k < len(ps):
                p = ps[k]
                if p == 0: st = dict(fg=None, bg=None, b=0, d=0, i=0, u=0, r=0)
                elif p == 1: st["b"] = 1
                elif p == 2: st["d"] = 1
                elif p == 3: st["i"] = 1
                elif p == 4: st["u"] = 1
                elif p == 7: st["r"] = 1
                elif p == 22: st["b"] = st["d"] = 0
                elif p == 23: st["i"] = 0
                elif p == 24: st["u"] = 0
                elif p == 27: st["r"] = 0
                elif 30 <= p <= 37: st["fg"] = PAL[p - 30]
                elif 90 <= p <= 97: st["fg"] = PAL[p - 82]
                elif 40 <= p <= 47: st["bg"] = PAL[p - 40]
                elif 100 <= p <= 107: st["bg"] = PAL[p - 92]
                elif p == 39: st["fg"] = None
                elif p == 49: st["bg"] = None
                elif p in (38, 48):
                    key = "fg" if p == 38 else "bg"
                    if ps[k + 1] == 5: st[key] = c256(ps[k + 2]); k += 2
                    elif ps[k + 1] == 2: st[key] = tuple(ps[k + 2:k + 5]); k += 4
                k += 1
        for ch in line[pos:]: cells.append((ch, dict(st)))
        plain = "".join(c for c, _ in cells)
        for rx in SCRUB:
            for m in rx.finditer(plain):
                for k in range(m.start(), m.end()): cells[k] = (" ", cells[k][1])
        rows.append(cells)
    return rows
def wide(ch): return ord(ch) >= 0x1f000 or 0x2e80 <= ord(ch) <= 0xa4cf or 0xff00 <= ord(ch) <= 0xff60
QUAD = {"█": 15, "▀": 3, "▄": 12, "▌": 5, "▐": 10, "▘": 1, "▝": 2, "▖": 4, "▗": 8, "▛": 7, "▜": 11, "▙": 13, "▟": 14, "▚": 9, "▞": 6}
BOX = {"─": "lr", "│": "ud", "┌": "rd", "┐": "ld", "└": "ru", "┘": "lu", "├": "udr", "┤": "udl", "┬": "lrd", "┴": "lru", "┼": "lrud",
       "╭": "rd", "╮": "ld", "╰": "ru", "╯": "lu", "━": "LR", "╌": "lr"}
def draw_pane(im, d, text, x0, y0):
    for r, cells in enumerate(parse(text)):
        xf = x0; y = y0 + r * CH
        for ch, st in cells:
            x = int(round(xf)); x2 = int(round(xf + CW * (2 if wide(ch) else 1))); cw = x2 - x
            w = 2 if wide(ch) else 1
            fg, bg = st["fg"] or FG, st["bg"] or BG
            if st["r"]: fg, bg = bg, fg
            if st["d"]: fg = tuple((a + b) // 2 for a, b in zip(fg, bg))
            if bg != BG: d.rectangle([x, y, x2 - 1, y + CH - 1], fill=bg)
            if ch in QUAD:
                q = QUAD[ch]; hx, hy = cw // 2, CH // 2
                for bit, (ax, ay, bx, by) in zip((1, 2, 4, 8), ((0, 0, hx, hy), (hx, 0, cw, hy), (0, hy, hx, CH), (hx, hy, cw, CH))):
                    if q & bit: d.rectangle([x + ax, y + ay, x + bx - 1, y + by - 1], fill=fg)
            elif ch in BOX:
                s = BOX[ch]; cx, cy = x + cw // 2, y + CH // 2; t = 3 if s.isupper() else 1; s = s.lower()
                if "l" in s: d.line([x, cy, cx, cy], fill=fg, width=t)
                if "r" in s: d.line([cx, cy, x2, cy], fill=fg, width=t)
                if "u" in s: d.line([cx, y, cx, cy], fill=fg, width=t)
                if "d" in s: d.line([cx, cy, cx, y + CH], fill=fg, width=t)
            elif ord(ch) >= 0x1f000:
                im.paste(emoji(ch), (x + 1, y + 3), emoji(ch))
            elif ch not in "  ":
                f = F[(st["b"], st["i"])]
                if not has(f, ch):
                    f = next((g for g in FALL if has(g, ch)), f)
                d.text((x, y + 1), ch, font=f, fill=fg)
            if st["u"]: d.line([x, y + CH - 3, x2 - 1, y + CH - 3], fill=fg)
            xf += CW * w
def frame(rec):
    im = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(im)
    xs = (PAD, PAD + (COLS[0] + 1) * CW)
    sep = int(PAD + COLS[0] * CW + CW / 2)
    d.line([sep, 0, sep, H], fill=(0x4a, 0x44, 0x38))
    d.line([0, TITLE - 8, W, TITLE - 8], fill=(0x4a, 0x44, 0x38))
    for x, label in zip(xs, ("the agent · Claude Code", "you · lox run, in a terminal of its own")):
        d.text((x, 6), label, font=UI, fill=(0xb9, 0xaf, 0x98))
    for p in (0, 1): draw_pane(im, d, rec["p"][p][0], xs[p], TITLE)
    return im
recs = [json.loads(l) for l in open(src)]
recs = [r for r in recs if T0 <= r["t"] <= T1]
lines = []; n = 0
for i, r in enumerate(recs):
    dur = (recs[i + 1]["t"] - r["t"]) if i + 1 < len(recs) else 4.0
    fn = f"{outdir}/f{n:05d}.png"; frame(r).save(fn); n += 1
    lines.append(f"file '{os.path.abspath(fn)}'\nduration {dur:.2f}\n")
lines.append(f"file '{os.path.abspath(fn)}'\n")
open(f"{outdir}/concat.txt", "w").write("".join(lines))
print(n, "frames", W, "x", H, "span", recs[0]["t"], recs[-1]["t"])
