"""
Sneppard Sniffer icon — 1970s national park poster aesthetic
Flat screenprint layers, limited warm palette, snow leopard eye

Usage (from the repo root):
    pip install Pillow
    python tools/generate-icons.py
"""
from PIL import Image, ImageDraw
import math, os

CREAM   = (237, 224, 200)
SAND    = (214, 190, 155)
RUST    = (176,  74,  44)
OXBLOOD = (122,  44,  38)
PINE    = ( 62,  78,  64)
CHAR    = ( 43,  38,  35)
SKY     = (203, 168, 128)

def almond(cx, cy, hw, hh_t, hh_b, n=90):
    top, bot = [], []
    for i in range(n + 1):
        t = math.pi * i / n
        top.append((cx + hw*math.cos(math.pi-t), cy - hh_t*math.sin(t)))
    for i in range(n + 1):
        t = math.pi * i / n
        bot.append((cx - hw*math.cos(math.pi-t), cy + hh_b*math.sin(t)))
    return top + bot

def draw_icon(size):
    sc = 4
    S = size * sc
    img = Image.new('RGBA', (S, S), (0,0,0,0))
    d = ImageDraw.Draw(img)
    cx, cy = S/2, S/2
    pad = S * 0.055
    R = (S/2) - pad

    d.ellipse([pad, pad, S-pad, S-pad], fill=(*CREAM,255))

    for frac, col in [(0.86, SAND), (0.70, SKY), (0.55, RUST)]:
        br = R * frac
        d.pieslice([cx-br, cy-br, cx+br, cy+br], start=180, end=360, fill=(*col,255))

    horizon = cy + R*0.30
    d.rectangle([pad, horizon, S-pad, S-pad], fill=(*PINE,255))

    mask = Image.new('L', (S,S), 0)
    ImageDraw.Draw(mask).ellipse([pad,pad,S-pad,S-pad], fill=255)
    base = Image.new('RGBA',(S,S),(0,0,0,0))
    base.paste(img, (0,0), mask)
    img = base
    d = ImageDraw.Draw(img)

    hw, hh_t, hh_b = R*0.86, R*0.44, R*0.36
    eye = almond(cx, cy, hw, hh_t, hh_b)
    d.polygon(eye, fill=(*CREAM,255))
    ow = max(2, int(S*0.028))
    for k in range(ow):
        d.polygon(almond(cx, cy, hw-k*0.6, hh_t-k*0.6, hh_b-k*0.6), outline=(*CHAR,255))

    ir = R*0.255
    d.ellipse([cx-ir,cy-ir,cx+ir,cy+ir], fill=(*RUST,255))
    for k in range(max(2,int(S*0.022))):
        e = ir-k*0.6
        d.ellipse([cx-e,cy-e,cx+e,cy+e], outline=(*CHAR,255))

    pw, ph = ir*0.30, ir*0.80
    d.ellipse([cx-pw, cy-ph, cx+pw, cy+ph], fill=(*CHAR,255))

    sd = ir*0.16
    d.ellipse([cx+ir*0.26, cy-ph*0.52, cx+ir*0.26+sd*2, cy-ph*0.52+sd*2], fill=(*CREAM,235))

    if size >= 48:
        rr = R*0.085
        for dx, dy in [(-R*0.66,-R*0.30), (-R*0.74,R*0.06), (R*0.66,-R*0.30), (R*0.74,R*0.06)]:
            sx, sy = cx+dx, cy+dy
            d.ellipse([sx-rr, sy-rr*0.8, sx+rr, sy+rr*0.8],
                      outline=(*CHAR,220), width=max(1,int(S*0.014)))

    rad = math.radians(-27)
    L = R*1.02
    x1,y1 = cx-L*math.cos(rad), cy-L*math.sin(rad)
    x2,y2 = cx+L*math.cos(rad), cy+L*math.sin(rad)
    slw = max(3,int(S*0.062))
    d.line([(x1,y1),(x2,y2)], fill=(*CHAR,255),    width=slw+max(2,int(S*0.018)))
    d.line([(x1,y1),(x2,y2)], fill=(*OXBLOOD,255), width=slw)

    d.ellipse([pad,pad,S-pad,S-pad], outline=(*CHAR,255), width=max(2,int(S*0.030)))

    out = Image.new('RGBA',(S,S),(0,0,0,0))
    out.paste(img,(0,0),mask)
    return out.resize((size,size), Image.LANCZOS)

os.makedirs('icons', exist_ok=True)
for s in [16,48,128]:
    draw_icon(s).save(f'icons/icon-{s}.png','PNG')
    print(f'✓ icon-{s}.png')
