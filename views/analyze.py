import requests
import streamlit as st

import engine
import ui

EXAMPLES = ["Summer2024!", "P@ssw0rd123", "correct horse battery staple"]

ui.hero(
    "Password audit console", "SecurePass", "Analyzer",
    "Strength, real entropy and breach exposure in one pass. "
    "Only 5 hex characters of a SHA-1 hash ever leave this app.",
)

password = st.text_input(
    "Password", key="password", type="password", max_chars=256,
    placeholder="Type a password, press Enter", label_visibility="collapsed",
)
with st.expander("Personal context (optional)", icon=":material/person_search:"):
    context = st.text_input(
        "Context", key="context", label_visibility="collapsed",
        placeholder="Your name, username, email, company, the site it's for",
    )
    st.caption("Checked locally and never sent. Attackers seed their wordlists with exactly this kind of public info.")

if not password:
    st.caption("No password handy? Try one:")
    with st.container(horizontal=True):
        for example in EXAMPLES:
            st.button(example, on_click=st.session_state.update, kwargs={"password": example})
        st.button("Random", icon=":material/casino:",
                  on_click=lambda: st.session_state.update(password=engine.generate_password(20)[0]))
    ui.tiles({
        "Breach check": ("HIBP", None, "k-anonymity range API"),
        "Entropy": ("2 ways", None, "naive vs pattern-aware"),
        "Policies": ("3", None, "NIST · PCI DSS · classic"),
    })
    st.stop()

s = engine.strength(password, context)
breach, breach_error = None, None
try:
    with st.spinner("Querying Have I Been Pwned…"):
        breach = engine.breach_check(password)
except requests.RequestException as e:
    breach_error = e
breaches = breach["count"] if breach else None

label = engine.verdict(s["bits"], breaches)
if breaches:
    note = (f"Seen <b>{breaches:,}</b> times in breach data. Attackers try leaked passwords first, "
            "so its entropy no longer protects it.")
elif breaches == 0:
    note = f"No breach record. One GPU against a fast hash needs <b>{s['crack_times'][-1]['text']}</b>."
else:
    note = "Breach check unavailable, so this rates pattern strength only."
ui.verdict_card(label, s["bits"], note, kicker="Effective entropy · verdict")

lost = s["naive_bits"] - s["bits"]
ui.tiles({
    "Naive entropy": (f"{s['naive_bits']:.0f} bits", None, "what most checkers report"),
    "Lost to patterns": (f"−{lost:.0f} bits" if lost >= 1 else "none", "#ff4d6d" if lost >= 1 else "#2ee6b6",
                         f"{lost / s['naive_bits']:.0%} of it was fake" if lost >= 1 else "no patterns found"),
    "Breach hits": ("?" if breaches is None else f"{breaches:,}", ui.VERDICT_COLORS["Compromised"] if breaches else None,
                    "Have I Been Pwned corpus"),
    "Length": (s["length"], None, "characters"),
})

ui.section("Pattern map", "how a cracker would split it")
reveal = st.toggle("Reveal characters", key="reveal")
ui.pattern_strip(s["sequence"], reveal)

ui.section("Time to crack", "log scale")
if breaches:
    st.caption("These assume blind guessing. A breached password falls to a wordlist attack almost at once.")
ui.crack_bars(s["crack_times"])

st.write("")
policy_tab, fix_tab, privacy_tab = st.tabs(["Policy", "How to fix", "Privacy"])

with policy_tab:
    name = st.segmented_control("Policy", list(engine.POLICIES), default="NIST SP 800-63B-4",
                                required=True, label_visibility="collapsed")
    summary, _ = engine.POLICIES[name]
    results = engine.check_policy(name, password, s, breaches)
    passed = sum(ok is True for _, ok in results)
    st.progress(passed / len(results), text=f"{passed} of {len(results)} rules met. {summary}")
    icons = {True: ":green[:material/check_circle:]", False: ":red[:material/cancel:]",
             None: ":orange[:material/help:]"}
    for rule, ok in results:
        st.markdown(f"{icons[ok]} {rule}{' · not checked' if ok is None else ''}")
    if not s["context"] and name.startswith("NIST"):
        st.caption("Add personal context above to run the context-word check.")

with fix_tab:
    fb = s["feedback"]
    if fb["warning"]:
        st.warning(fb["warning"], icon=":material/warning:")
    tips = list(fb["suggestions"])
    if s["context_hits"]:
        tips.insert(0, f"It contains personal info ({', '.join(s['context_hits'])}). "
                       "Anyone who looks you up can guess that part.")
    if breaches:
        tips.insert(0, "Retire this password everywhere you use it. It is on attackers' lists, "
                       "so no amount of length or symbols saves it.")
    if s["bits"] < 64:
        tips.append("Go long and random: five or more unrelated words, or 16+ characters from a password manager. "
                    "The Generate tab makes both.")
    if breaches is None:
        tips.append("Breach status is unknown. Check again once Have I Been Pwned is reachable.")
    if tips:
        st.markdown("\n".join(f"- {t}" for t in dict.fromkeys(tips)))
    else:
        st.success("Nothing to fix. Keep it in a password manager and never reuse it.",
                   icon=":material/verified_user:")

with privacy_tab:
    if breach:
        ui.hash_reveal(breach["prefix"])
        st.markdown(
            f"Have I Been Pwned answered with **{breach['candidates']:,}** breached hashes sharing that "
            "prefix, padded with decoys so even the response size gives nothing away. "
            "The match against the other 35 characters ran here."
        )
    else:
        st.error(f"Could not reach Have I Been Pwned ({type(breach_error).__name__}).")
    st.caption("Run locally, the password never leaves your machine. On a hosted copy it travels to that "
               "server over HTTPS, so audit real passwords on a local copy.")
