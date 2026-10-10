import hashlib
import statistics

import pandas as pd
import streamlit as st

import engine
import ui

MAX_ENTRIES = 1000
ORDER = ["Compromised", "Very weak", "Weak", "Fair", "Strong", "Very strong"]

ui.hero(
    "Batch audit", "Audit the whole", "vault",
    "Breached, weak and reused passwords across a password-manager export or any list. "
    "Every password is checked the same k-anonymous way.",
)
st.warning("Local copy only. A vault export holds every password you own; never feed one to a hosted copy of this app.",
           icon=":material/lock:")

source = st.segmented_control("Source", ["Upload export", "Paste list"], default="Upload export", required=True,
                              label_visibility="collapsed")
if source == "Upload export":
    upload = st.file_uploader("CSV export from Bitwarden, 1Password, Chrome, Firefox, KeePass or LastPass, "
                              "or a .txt list with one password per line", type=["csv", "txt"])
    text = upload.getvalue().decode("utf-8-sig", errors="replace") if upload else ""
else:
    text = st.text_area("Passwords, one per line", height=180, placeholder="hunter2\nSummer2024!\n…")

entries = engine.parse_entries(text) if text else []
if not entries:
    ui.tiles({
        "Breached": ("HIBP", None, "every entry, prefix only"),
        "Reused": ("×N", None, "same password, many sites"),
        "Weak": ("bits", None, "pattern-aware entropy"),
    })
    st.stop()
if len(entries) > MAX_ENTRIES:
    st.info(f"Auditing the first {MAX_ENTRIES:,} of {len(entries):,} entries.")
    entries = entries[:MAX_ENTRIES]

# Results live in session state, keyed by a hash of the input so stale results never show.
key = hashlib.sha256(text.encode()).hexdigest()
unique = len({p for _, p in entries})
st.caption(f"{len(entries):,} entries found, {unique:,} unique passwords.")
if st.button("Run audit", type="primary", icon=":material/radar:"):
    bar = st.progress(0.0, text="Checking…")
    rows = engine.audit([p for _, p in entries], progress=lambda f: bar.progress(f, text=f"Checking… {f:.0%}"))
    bar.empty()
    st.session_state.audit = (key, rows)
if st.session_state.get("audit", (None,))[0] != key:
    st.stop()
rows = st.session_state.audit[1]

counts = {v: sum(r["verdict"] == v for r in rows) for v in ORDER}
breached = counts["Compromised"]
reused = sum(r["reused"] > 1 for r in rows)
weak = sum(r["bits"] < 45 for r in rows)
ui.tiles({
    "Entries": (f"{len(rows):,}", None, f"{unique:,} unique"),
    "Breached": (f"{breached:,}", ui.VERDICT_COLORS["Compromised"] if breached else "#2ee6b6", "change these first"),
    "Reused": (f"{reused:,}", ui.VERDICT_COLORS["Weak"] if reused else "#2ee6b6", "entries sharing a password"),
    "Weak": (f"{weak:,}", ui.VERDICT_COLORS["Fair"] if weak else "#2ee6b6",
             f"under 45 bits · median {statistics.median(r['bits'] for r in rows):.0f}"),
})
ui.distribution([(v, n) for v, n in counts.items() if n])
if any(r["breaches"] is None for r in rows):
    st.caption("Some breach checks failed (network), so those entries are rated on patterns only.")

ui.section("Findings", "worst first")
reveal = st.toggle("Reveal passwords")
df = pd.DataFrame([
    {"Entry": label, "Password": p if reveal else "•" * min(len(p), 12), "Verdict": r["verdict"],
     "Entropy": round(r["bits"], 1), "Breach hits": r["breaches"], "Reused": r["reused"]}
    for (label, p), r in zip(entries, rows)
])
df = df.sort_values(["Verdict", "Reused", "Entropy"], ascending=[True, False, True],
                    key=lambda c: c.map(ORDER.index) if c.name == "Verdict" else c)
st.dataframe(
    df.style.map(lambda v: f"color: {ui.VERDICT_COLORS[v]}; font-weight: 600", subset=["Verdict"])
            .map(lambda n: "color: #ff9f43" if n > 1 else "", subset=["Reused"]),
    hide_index=True,
    column_config={
        "Entropy": st.column_config.ProgressColumn("Entropy", min_value=0, max_value=128, format="%.0f bits"),
        "Breach hits": st.column_config.NumberColumn(format="localized"),
        "Reused": st.column_config.NumberColumn(format="%d×"),
    },
)
st.download_button("Download report (no passwords)", df.drop(columns="Password").to_csv(index=False),
                   file_name="securepass-audit.csv", mime="text/csv", icon=":material/download:")
