#!/usr/bin/env python3
"""Generate a Lock Family README banner: docs/assets/banner-light.svg and banner-dark.svg.

    python3 tools/banner_svg.py --name locksql \\
        --tagline "Your agent writes the query. You hold the key." \\
        --logo site/assets/logo.svg --fonts site/assets/fonts --out docs/assets

The family style (lockfamily docs/identity.md): a paper (light) or carbon
(dark) ticket with an ink border and a perforation, the Lock's padlock logo
(lockfamily assets/<lock>.svg; assets/mark.svg for a Lock without its own),
a mono label, the lowercase wordmark in Zilla Slab and the tagline in Source
Serif 4.

GitHub shows a README image through <img>, which loads no web font. So the
text is drawn as outlines from the family's own woff2 fonts (fontTools and
brotli: `pip install fonttools brotli`): the banner looks the same
everywhere and loads nothing. Without fontTools, or with --text, it writes
<text> with a safe font stack instead (Rockwell/Georgia, Menlo/Consolas).

Each file holds one theme, fixed colours, no media query: the README picks
one with <picture> and prefers-color-scheme. Python 3 standard library plus
fontTools; --check fails when the files on disk differ from what it writes.
"""

import argparse
import os
import re
import sys
from xml.sax.saxutils import escape

W, H = 1200, 300

# The identity tokens (lockfamily assets/tokens.css), per theme.
THEMES = {
    'light': {'paper': '#f4efe4', 'card': '#fffcf5', 'ink': '#1d1b17', 'ink2': '#575146', 'rule': '#b9af98'},
    'dark': {'paper': '#16140f', 'card': '#25221b', 'ink': '#ede6d6', 'ink2': '#b2a994', 'rule': '#4a4438'},
}

FONTS = {
    'display': ('zilla-slab-700.woff2', '"Zilla Slab", Rockwell, "Roboto Slab", Georgia, serif', 700),
    'text': ('source-serif-4-400.woff2', '"Source Serif 4", "Iowan Old Style", Georgia, serif', 400),
    'mono': ('ibm-plex-mono-600.woff2', '"IBM Plex Mono", Menlo, Consolas, monospace', 600),
}


class Outliner:
    """Text to SVG path data, from a woff2 font, with the font's kerning pairs."""

    def __init__(self, path):
        from fontTools.ttLib import TTFont
        self.font = TTFont(path)
        self.upm = self.font['head'].unitsPerEm
        self.cmap = self.font.getBestCmap()
        self.glyphs = self.font.getGlyphSet()
        self.hmtx = self.font['hmtx']
        self.kern = self._pairs()

    def _pairs(self):
        pairs = {}
        if 'GPOS' not in self.font:
            return pairs
        for lookup in self.font['GPOS'].table.LookupList.Lookup:
            for st in lookup.SubTable:
                if lookup.LookupType == 9:
                    st = st.ExtSubTable
                if getattr(st, 'LookupType', 2) != 2 or not hasattr(st, 'Format'):
                    continue
                if st.Format == 1:
                    firsts = st.Coverage.glyphs
                    for i, ps in enumerate(st.PairSet):
                        for pvr in ps.PairValueRecord:
                            v = getattr(pvr.Value1, 'XAdvance', 0) if pvr.Value1 else 0
                            if v:
                                pairs.setdefault((firsts[i], pvr.SecondGlyph), v)
                elif st.Format == 2:
                    c1 = st.ClassDef1.classDefs if st.ClassDef1 else {}
                    c2 = st.ClassDef2.classDefs if st.ClassDef2 else {}
                    for g1 in st.Coverage.glyphs:
                        rec = st.Class1Record[c1.get(g1, 0)]
                        for g2, k2 in c2.items():
                            v = getattr(rec.Class2Record[k2].Value1, 'XAdvance', 0) if rec.Class2Record[k2].Value1 else 0
                            if v:
                                pairs.setdefault((g1, g2), v)
        return pairs

    def names(self, text):
        out = []
        for ch in text:
            name = self.cmap.get(ord(ch))
            if name is None:
                raise KeyError('glyph missing for %r' % ch)
            out.append(name)
        return out

    def width(self, text, size, tracking=0.0):
        return self._layout(text, size, tracking)[1]

    def _layout(self, text, size, tracking):
        names = self.names(text)
        scale = size / self.upm
        x, placed = 0.0, []
        for i, n in enumerate(names):
            placed.append((n, x))
            x += self.hmtx[n][0] * scale + tracking
            if i + 1 < len(names):
                x += self.kern.get((n, names[i + 1]), 0) * scale
        return placed, x - tracking

    def path(self, text, x0, baseline, size, tracking=0.0):
        from fontTools.pens.svgPathPen import SVGPathPen
        from fontTools.pens.transformPen import TransformPen
        placed, _ = self._layout(text, size, tracking)
        scale = size / self.upm
        parts = []
        for name, x in placed:
            pen = SVGPathPen(self.glyphs, ntos=lambda v: ('%.2f' % v).rstrip('0').rstrip('.'))
            self.glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x0 + x, baseline)))
            d = pen.getCommands()
            if d:
                parts.append(d)
        return ''.join(parts)


def logo_body(path, theme):
    """The logo's drawing, with its classes bound to one theme's colours."""
    with open(path, encoding='utf-8') as f:
        svg = f.read()
    inner = re.sub(r'(?s)^.*?<svg[^>]*>', '', svg)
    inner = re.sub(r'(?s)</svg>\s*$', '', inner)
    inner = re.sub(r'(?s)<(title|desc|style)>.*?</\1>', '', inner).strip()
    t = THEMES[theme]
    style = ('.lg .i{stroke:%s}.lg .f{fill:%s}.lg .p{fill:%s}.lg .d{stroke:%s}'
             % (t['ink'], t['ink'], t['card'], t['ink2']))
    return style, inner


def fit(measure, text, size, room, floor):
    while size > floor and measure(text, size) > room:
        size -= 1
    return size


def banner(theme, name, tagline, label, logo, fonts_dir, as_text):
    t = THEMES[theme]
    style, drawing = logo_body(logo, theme)
    x_text, room = 300, W - 300 - 56
    out = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s">'
           % (W, H, W, H, escape('%s: %s' % (name, tagline), {'"': '&quot;'})),
           '<title>%s</title>' % escape('%s: %s' % (name, tagline)),
           '<style>%s</style>' % style,
           # The ticket: paper face, ink border, a perforation before the stub.
           '<rect x="1" y="1" width="%d" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="2"/>' % (W - 2, H - 2, t['paper'], t['ink']),
           '<path d="M268 24 V%d" stroke="%s" stroke-width="2" stroke-dasharray="6 6"/>' % (H - 24, t['rule']),
           '<g class="lg" transform="translate(40 52) scale(1.53)">%s</g>' % drawing]
    rows = [('mono', label.upper(), 92, 19, 2.4, t['ink2']),
            ('display', name, 192, 112, 0.0, t['ink']),
            ('text', tagline, 260, 36, 0.0, t['ink'])]
    outliners = {}
    if not as_text:
        try:
            outliners = {k: Outliner(os.path.join(fonts_dir, FONTS[k][0])) for k in FONTS}
        except ImportError:
            print('banner_svg: fontTools not found, writing <text> (pip install fonttools brotli for outlines)',
                  file=sys.stderr)
    for kind, text, baseline, size, tracking, colour in rows:
        if outliners:
            o = outliners[kind]
            size = fit(lambda s, z: o.width(s, z, tracking), text, size, room, 14)
            out.append('<path fill="%s" d="%s"/>' % (colour, o.path(text, x_text, baseline, size, tracking)))
        else:
            size = fit(lambda s, z: len(s) * z * (0.6 if kind == 'mono' else 0.5), text, size, room, 14)
            out.append('<text x="%d" y="%d" fill="%s" font-family=\'%s\' font-weight="%d" font-size="%d"%s>%s</text>'
                       % (x_text, baseline, colour, FONTS[kind][1], FONTS[kind][2], size,
                          ' letter-spacing="%.1f"' % tracking if tracking else '', escape(text)))
    out.append('</svg>')
    return '\n'.join(out) + '\n'


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--name', required=True, help='the Lock, lowercase: locksql')
    p.add_argument('--tagline', required=True, help='one short sentence')
    p.add_argument('--label', default='A Lock of the Lock Family', help='the mono label above the name')
    p.add_argument('--logo', required=True, help="the Lock's family logo SVG (lockfamily assets/<lock>.svg)")
    p.add_argument('--fonts', default='site/assets/fonts', help='directory of the family woff2 fonts')
    p.add_argument('--out', default='docs/assets', help='output directory')
    p.add_argument('--text', action='store_true', help='write <text> with a font stack instead of outlines')
    p.add_argument('--check', action='store_true', help='fail if the files on disk differ')
    a = p.parse_args(argv)
    bad = 0
    for theme in ('light', 'dark'):
        svg = banner(theme, a.name, a.tagline, a.label, a.logo, a.fonts, a.text)
        dest = os.path.join(a.out, 'banner-%s.svg' % theme)
        if a.check:
            with open(dest, encoding='utf-8') as f:
                if f.read() != svg:
                    print('banner_svg: %s is out of date' % dest, file=sys.stderr)
                    bad = 1
            continue
        os.makedirs(a.out, exist_ok=True)
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(svg)
        print('wrote %s (%d bytes)' % (dest, len(svg)))
    return bad


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
