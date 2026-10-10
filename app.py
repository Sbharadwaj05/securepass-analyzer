"""SecurePass Analyzer: Streamlit entry point. Logic lives in engine.py, building blocks in ui.py."""
import streamlit as st

import ui

st.set_page_config(page_title="SecurePass Analyzer", page_icon=":material/shield_lock:")
ui.style()

page = st.navigation(
    [
        st.Page("views/analyze.py", title="Analyze", icon=":material/shield_lock:", default=True),
        st.Page("views/generate.py", title="Generate", icon=":material/casino:"),
        st.Page("views/audit.py", title="Batch audit", icon=":material/fact_check:"),
    ],
    position="top",
)
body = st.container()  # pages call st.stop(), so the footer goes in first and the page fills the slot above it
ui.footer()
with body:
    page.run()
