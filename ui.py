"""HTML/CSS building blocks shared by the pages. Escape anything user-derived."""
import html
import math

import streamlit as st

import engine

VERDICT_COLORS = {
    "Compromised": "#ff3b5c",
    "Very weak": "#ff4d6d",
    "Weak": "#ff9f43",
    "Fair": "#f7c948",
    "Strong": "#4ade80",
    "Very strong": "#2ee6b6",
}

# pattern kind -> (name, color)
PATTERNS = {
    "dictionary": ("Dictionary word", "#fb7185"),
    "user_inputs": ("Personal info", "#e879f9"),
    "spatial": ("Keyboard walk", "#fb923c"),
    "repeat": ("Repeat", "#facc15"),
    "sequence": ("Sequence", "#a78bfa"),
    "regex": ("Year", "#60a5fa"),
    "date": ("Date", "#60a5fa"),
    "bruteforce": ("Random", "#2ee6b6"),
}

# No literal "<" anywhere in here: the st.html sanitiser drops a <style> block containing one.
CSS = """
:root { --bg: #07090d; --line: rgba(255,255,255,.08); --muted: rgba(230,237,243,.58);
  --accent: #2ee6b6; --accent2: #38bdf8; --mono: "JetBrains Mono", ui-monospace, monospace; }
.stApp {
  background:
    radial-gradient(900px 420px at 50% -140px, rgba(46,230,182,.14), transparent 70%),
    radial-gradient(700px 380px at 95% -100px, rgba(56,189,248,.10), transparent 70%),
    radial-gradient(ellipse 120% 75% at 50% 0%, transparent 30%, var(--bg) 78%),
    linear-gradient(rgba(255,255,255,.04) 1px, transparent 1px) 0 0 / 36px 36px,
    linear-gradient(90deg, rgba(255,255,255,.04) 1px, transparent 1px) 0 0 / 36px 36px,
    var(--bg) !important;
}
[data-testid="stHeader"] { background: rgba(7,9,13,.72); backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--line); }
[data-testid="stBaseButton-primary"] { color: #04130e !important; font-weight: 600;
  box-shadow: 0 0 24px -6px rgba(46,230,182,.7); }
.st-key-password input { font-family: var(--mono) !important; font-size: 1.1rem !important;
  letter-spacing: .06em; padding-top: .8rem; padding-bottom: .8rem; }
.st-key-password [data-baseweb="input"] { border-radius: 14px; transition: box-shadow .2s; }
.st-key-password [data-baseweb="input"]:focus-within {
  box-shadow: 0 0 0 1px var(--accent), 0 0 28px -4px rgba(46,230,182,.45); }
.st-key-genbox pre { padding: 1.1rem 1.2rem !important; border: 1px solid rgba(46,230,182,.35);
  box-shadow: 0 0 32px -10px rgba(46,230,182,.55); }
.st-key-genbox code { font-size: 1.3rem !important; color: #e6edf3 !important; }

@keyframes rise { from { opacity: 0; transform: translateY(8px); } }
@keyframes sweep { from { stroke-dashoffset: var(--len); } }
@keyframes grow { from { width: 0; } }
@keyframes pulse { 50% { opacity: .35; } }

.hero { padding: 4px 0 16px; animation: rise .5s ease both; }
.kicker { font: 500 .7rem/1 var(--mono); letter-spacing: .2em; text-transform: uppercase;
  color: var(--accent); display: flex; align-items: center; gap: 8px; }
.kicker .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--accent);
  box-shadow: 0 0 10px var(--accent); animation: pulse 2s ease-in-out infinite; }
.hero h1 { font-size: clamp(2rem, 7vw, 3rem); font-weight: 700; letter-spacing: -.035em;
  line-height: 1.05; margin: 14px 0 10px; padding: 0; }
.grad { background: linear-gradient(90deg, var(--accent), var(--accent2)); -webkit-background-clip: text;
  background-clip: text; color: transparent; }
.hero p { color: var(--muted); margin: 0; max-width: 580px; }

.card { background: linear-gradient(180deg, rgba(255,255,255,.045), rgba(255,255,255,.012));
  border: 1px solid var(--line); border-radius: 18px; padding: 18px 22px; animation: rise .45s ease both; }
.verdict { display: flex; gap: 22px; align-items: center;
  border-color: color-mix(in srgb, var(--c) 42%, transparent);
  background: radial-gradient(420px 180px at 0% 50%, color-mix(in srgb, var(--c) 17%, transparent), transparent 70%),
    linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.01));
  box-shadow: 0 0 48px -16px color-mix(in srgb, var(--c) 55%, transparent); }
@property --p { syntax: "\\3c number>"; inherits: true; initial-value: 0; }
@keyframes ring { from { --p: 0; } }
.gauge { width: 118px; height: 118px; flex: none; position: relative; border-radius: 50%;
  display: grid; place-content: center; text-align: center; box-shadow: 0 0 36px -10px var(--c); }
.ring { position: absolute; inset: 0; border-radius: 50%; animation: ring 1.2s cubic-bezier(.2,.8,.2,1) both;
  background: conic-gradient(var(--c) calc(var(--p) * 1%), rgba(255,255,255,.07) 0);
  -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 9px), #000 calc(100% - 8px));
  mask: radial-gradient(farthest-side, transparent calc(100% - 9px), #000 calc(100% - 8px)); }
.g-num { font: 700 2rem/1 var(--mono); color: #e6edf3; }
.g-unit { font: 500 .58rem var(--mono); color: rgba(230,237,243,.55); letter-spacing: .25em; margin-top: 6px; }
.v-kicker { font: 500 .68rem var(--mono); letter-spacing: .18em; text-transform: uppercase; color: var(--muted); }
.v-label { font-size: 2rem; font-weight: 700; color: var(--c); line-height: 1.1; letter-spacing: -.02em;
  text-shadow: 0 0 24px color-mix(in srgb, var(--c) 45%, transparent); margin: 4px 0 6px; }
.v-note { color: rgba(230,237,243,.86); }
@media (max-width: 560px) { .verdict { flex-direction: column; align-items: flex-start; } }

.sec { display: flex; align-items: baseline; gap: 12px; margin: 30px 0 12px; }
.sec b { font: 600 .74rem var(--mono); letter-spacing: .18em; text-transform: uppercase; color: #e6edf3; }
.sec span { font: .7rem var(--mono); color: var(--muted); }
.sec::after { content: ""; flex: 1; height: 1px; background: linear-gradient(90deg, var(--line), transparent); }

.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-top: 12px; }
.tile { background: rgba(255,255,255,.025); border: 1px solid var(--line); border-radius: 14px;
  padding: 12px 14px; animation: rise .45s ease both; }
.tile small { display: block; font: 500 .64rem var(--mono); letter-spacing: .14em; text-transform: uppercase;
  color: var(--muted); margin-bottom: 6px; }
.tile b { font: 600 1.3rem var(--mono); color: var(--c, #e6edf3); letter-spacing: -.02em; }
.tile em { display: block; font-style: normal; font-size: .76rem; color: var(--muted); margin-top: 4px; }

.strip { display: flex; flex-wrap: wrap; gap: 5px; }
.seg { flex: var(--w) 1 0; min-width: 40px; border-radius: 10px; padding: 9px 9px 8px; overflow: hidden;
  background: color-mix(in srgb, var(--c) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--c) 38%, transparent); border-top: 3px solid var(--c);
  animation: rise .4s ease both; animation-delay: calc(var(--i) * 70ms); }
.seg .chars { font: 500 1rem var(--mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.seg .meta { font: 600 .6rem var(--mono); letter-spacing: .08em; text-transform: uppercase; color: var(--c);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 5px; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 10px; font: .7rem var(--mono); color: var(--muted); }
.legend i { display: inline-block; width: 8px; height: 8px; border-radius: 2px; background: var(--c); margin-right: 6px; }

.bars { display: grid; gap: 14px; }
.bar-head { display: flex; justify-content: space-between; gap: 12px; font-size: .9rem; margin-bottom: 6px; }
.bar-head small { font: .68rem var(--mono); color: var(--muted); margin-left: 8px; white-space: nowrap; }
.bar-head b { font: 600 .85rem var(--mono); color: var(--c); text-align: right; }
.bar { position: relative; height: 8px; background: rgba(255,255,255,.06); border-radius: 99px; }
.bar .fill { position: absolute; inset: 0 auto 0 0; width: var(--w); border-radius: 99px;
  background: linear-gradient(90deg, color-mix(in srgb, var(--c) 35%, transparent), var(--c));
  box-shadow: 0 0 14px -2px var(--c); animation: grow 1.1s cubic-bezier(.2,.8,.2,1) both; }
.bar .tick { position: absolute; top: -3px; bottom: -3px; width: 1px; background: rgba(255,255,255,.22); }
.scale { position: relative; height: 16px; font: .6rem var(--mono); color: var(--muted); margin-bottom: 6px; }
.scale span { position: absolute; transform: translateX(-50%); white-space: nowrap; }

.hash { font: 500 1rem var(--mono); letter-spacing: .1em; word-break: break-all; padding: 14px 16px;
  border-radius: 12px; background: rgba(0,0,0,.35); border: 1px dashed rgba(255,255,255,.14); }
.hash .sent { color: #04130e; background: var(--accent); padding: 2px 5px; border-radius: 5px;
  box-shadow: 0 0 18px rgba(46,230,182,.55); }
.hash .kept { color: rgba(230,237,243,.25); }
.hash-legend { display: flex; justify-content: space-between; gap: 12px; font: .68rem var(--mono);
  color: var(--muted); margin: 8px 0 14px; }
.hash-legend span:first-child { color: var(--accent); }

.dist { display: flex; gap: 3px; height: 14px; border-radius: 99px; overflow: hidden; margin-top: 14px; }
.dist div { flex: var(--n) 1 0; background: var(--c); box-shadow: 0 0 12px -2px var(--c);
  animation: rise .5s ease both; }

.foot { margin-top: 56px; padding-top: 14px; border-top: 1px solid var(--line); display: flex;
  justify-content: space-between; flex-wrap: wrap; gap: 8px; font: .68rem var(--mono); color: var(--muted); }
"""


def style():
    st.html(f"<style>{CSS}</style>")


def kind(m):
    return "user_inputs" if m.get("dictionary_name") == "user_inputs" else m["pattern"]


def detail(m):
    """One-line explanation of a match, for tooltips and tables."""
    if m["pattern"] == "dictionary":
        extras = [name for name, on in (("leetspeak", m.get("l33t")), ("reversed", m.get("reversed"))) if on]
        source = "your context" if kind(m) == "user_inputs" else m["dictionary_name"].replace("_", " ")
        return ", ".join([f"“{m['matched_word']}”, #{m['rank']:,} in {source}", *extras])
    if m["pattern"] == "repeat":
        return f"“{m['base_token']}” × {m['repeat_count']}"
    if m["pattern"] == "spatial":
        return f"{m['graph']} keyboard, {m['turns']} turn(s)"
    return PATTERNS[kind(m)][0]


def hero(kicker, title, accent, sub):
    st.html(
        f"<div class='hero'><div class='kicker'><span class='dot'></span>{kicker}</div>"
        f"<h1>{title} <span class='grad'>{accent}</span></h1><p>{sub}</p></div>"
    )


def section(title, hint=""):
    st.html(f"<div class='sec'><b>{title}</b><span>{hint}</span></div>")


def verdict_card(label, bits, note, kicker="Verdict"):
    """Glowing card with an animated entropy ring (full at 128 bits)."""
    color = VERDICT_COLORS[label]
    st.html(
        f"<div class='card verdict' style='--c:{color}'>"
        f"<div class='gauge' style='--p:{min(bits, 128) / 1.28:.1f}'><div class='ring'></div>"
        f"<div class='g-num'>{bits:.0f}</div><div class='g-unit'>BITS</div></div>"
        f"<div><div class='v-kicker'>{kicker}</div><div class='v-label'>{label}</div>"
        f"<div class='v-note'>{note}</div></div></div>"
    )


def tiles(items):
    """Stat cards. items: {label: value | (value, color) | (value, color, sub)}. Trusted text only."""
    cells = []
    for label, value in items.items():
        value, color, sub = (*value, None, None)[:3] if isinstance(value, tuple) else (value, None, None)
        style_attr = f" style='--c:{color}'" if color else ""
        sub_html = f"<em>{sub}</em>" if sub else ""
        cells.append(f"<div class='tile'{style_attr}><small>{label}</small><b>{value}</b>{sub_html}</div>")
    st.html(f"<div class='tiles'>{''.join(cells)}</div>")


def pattern_strip(sequence, reveal):
    """The password as coloured blocks, one per pattern, widths proportional to length."""
    segs, seen = [], {}
    for i, m in enumerate(sequence):
        name, color = PATTERNS[kind(m)]
        seen[name] = color
        chars = html.escape(m["token"]) if reveal else "•" * len(m["token"])
        segs.append(
            f"<div class='seg' style='--w:{len(m['token'])};--c:{color};--i:{i}' title='{html.escape(detail(m))}'>"
            f"<div class='chars'>{chars}</div><div class='meta'>{m['bits']:.0f}b</div></div>"
        )
    legend = "".join(f"<span style='--c:{c}'><i></i>{n}</span>" for n, c in seen.items())
    st.html(f"<div class='strip'>{''.join(segs)}</div><div class='legend'>{legend}</div>")


def _time_color(seconds):
    for limit, color in ((86400, "#ff4d6d"), (engine.YEAR, "#ff9f43"), (1000 * engine.YEAR, "#f7c948"),
                         (engine.UNIVERSE, "#4ade80")):
        if seconds < limit:
            return color
    return "#2ee6b6"


def crack_bars(rows):
    """Log-scale bars from 1 second to 10^20 seconds, with day / year / universe ticks."""
    pct = lambda s: min(max(math.log10(max(s, 1)) / 20, 0.015), 1) * 100  # noqa: E731
    marks = [("1 day", 86400), ("1 yr", engine.YEAR), ("1K yrs", 1000 * engine.YEAR), ("universe", engine.UNIVERSE)]
    ticks = "".join(f"<i class='tick' style='left:{pct(s):.1f}%'></i>" for _, s in marks)
    scale = "".join(f"<span style='left:{pct(s):.1f}%'>{name}</span>" for name, s in marks)
    out = [f"<div class='scale'>{scale}</div><div class='bars'>"]
    for r in rows:
        out.append(
            f"<div style='--c:{_time_color(r['seconds'])}'><div class='bar-head'>"
            f"<span>{r['attack']}<small>{r['rate']}</small></span><b>{r['text']}</b></div>"
            f"<div class='bar'><div class='fill' style='--w:{pct(r['seconds']):.1f}%'></div>{ticks}</div></div>"
        )
    st.html("".join(out) + "</div>")


def hash_reveal(prefix):
    st.html(
        f"<div class='hash'><span class='sent'>{prefix}</span><span class='kept'>{'•' * 35}</span></div>"
        "<div class='hash-legend'><span>▲ sent: 5 of 40 hex chars</span><span>35 never leave this app</span></div>"
    )


def distribution(counts):
    """counts: [(verdict, n)] as one stacked bar plus legend."""
    segs = "".join(f"<div style='--n:{n};--c:{VERDICT_COLORS[v]}' title='{v}: {n}'></div>" for v, n in counts)
    legend = "".join(f"<span style='--c:{VERDICT_COLORS[v]}'><i></i>{v} {n}</span>" for v, n in counts)
    st.html(f"<div class='dist'>{segs}</div><div class='legend'>{legend}</div>")


def footer():
    st.html(
        "<div class='foot'><span>SHA-1 k-anonymity · zxcvbn patterns · secrets RNG</span>"
        "<span>Nothing stored. Nothing logged.</span></div>"
    )
