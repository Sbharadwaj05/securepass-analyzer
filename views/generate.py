import requests
import streamlit as st

import engine
import ui

SEPARATORS = {"-": "hyphen", ".": "dot", "_": "underscore", " ": "space", "": "none"}

ui.hero(
    "Generator", "Make one that", "holds",
    "Random passwords and diceware-style passphrases from Python's secrets module. "
    "Made on the fly, never stored.",
)

mode = st.segmented_control("Type", ["Passphrase", "Random"], default="Passphrase", required=True,
                            key="gen_mode", label_visibility="collapsed")
if mode == "Passphrase":
    left, right = st.columns(2)
    words = left.slider("Words", 4, 10, 6)
    sep = right.selectbox("Separator", list(SEPARATORS), format_func=lambda s: f"{SEPARATORS[s]}  {s}".strip())
    with st.container(horizontal=True):
        cap = st.toggle("Capitalise", True)
        num = st.toggle("Add a number", False)
    options = ("phrase", words, sep, cap, num)
    make = lambda: engine.generate_passphrase(words, sep, cap, num)  # noqa: E731
else:
    length = st.slider("Length", 8, 64, 20)
    with st.container(horizontal=True):
        lower = st.toggle("a-z", True)
        upper = st.toggle("A-Z", True)
        digits = st.toggle("0-9", True)
        symbols = st.toggle("!@#", True)
        avoid = st.toggle("No look-alikes", False, help="Skips I l 1 | O 0 o and quotes.")
    options = ("random", length, lower, upper, digits, symbols, avoid)
    make = lambda: engine.generate_password(length, lower, upper, digits, symbols, avoid)  # noqa: E731

if st.button("Regenerate", type="primary", icon=":material/casino:") or st.session_state.get("gen_options") != options:
    st.session_state.gen, st.session_state.gen_options = make(), options
password, bits = st.session_state.gen

with st.container(key="genbox"):
    st.code(password, language=None, wrap_lines=True)

try:
    breaches = engine.breach_check(password)["count"]
except requests.RequestException:
    breaches = None
label = engine.verdict(bits, breaches)
estimate = engine.strength(password)["bits"]
ui.tiles({
    "Generation entropy": (f"{bits:.0f} bits", ui.VERDICT_COLORS[label], "exact: counts the random choices"),
    "Pattern estimate": (f"{estimate:.0f} bits", None, "what cracking tools would guess"),
    "Breach hits": ("?" if breaches is None else f"{breaches:,}", None, "checked via k-anonymity"),
    "Verdict": (label, ui.VERDICT_COLORS[label], "by generation entropy"),
})
if mode == "Passphrase":
    st.caption(f"Each word is one of {len(engine.WORDS):,} common English words, so 12 bits apiece even if an "
               "attacker knows the wordlist. The pattern estimate can read higher because it doesn't know that. "
               "Common words are the point: easy to remember, still random.")

ui.section("Time to crack", "from generation entropy")
ui.crack_bars(engine.crack_times(bits))

st.write("")
if st.button("Analyze in depth", icon=":material/arrow_forward:"):
    st.session_state.password = password
    st.switch_page("views/analyze.py")
