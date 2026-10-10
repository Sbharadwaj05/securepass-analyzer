# SecurePass Analyzer

A password auditing tool that checks how strong a password really is and whether it has already turned up in a known data breach. Built with Python and Streamlit.

## The goal

Most password checkers only look at a password in isolation and count its length or whether it has a symbol in it. That misses the real problem. A password can look strong and still be useless if it has already leaked in a breach somewhere, because attackers work from lists of exactly those leaked passwords. SecurePass Analyzer was built to close that gap, by scoring a password on its actual strength and checking it against real breached data at the same time, so a user finds out not just whether their password looks good but whether it is already known to the people they are trying to keep out.

`Summer2024!` shows the problem well. It passes five of six classic complexity rules and a naive checker rates it at 72 bits. Pattern analysis puts it at 26 bits (a capitalised dictionary word, a digit sequence and a symbol), and Have I Been Pwned has seen it more than 3,000 times.

## What it does

- **Breach detection.** It checks a password against the Have I Been Pwned database, so a password that has appeared in a real leak is flagged as compromised however strong it looks on paper.
- **Two entropy scores.** *Naive entropy* is length × log2(character pool), the figure most checkers stop at. *Effective entropy* is the cheapest way an attacker could build the password from known patterns: dictionary words, leetspeak, keyboard walks, repeats, sequences, dates and random characters. The gap between the two shows how much of a password's apparent strength is fake.
- **Crack-time estimates.** The effective entropy is turned into time-to-crack for four attack scenarios, from a rate-limited online login up to a fast hash on a single modern GPU.
- **Policy compliance scoring.** It scores a password against NIST SP 800-63B-4, PCI DSS 4.0 or classic corporate complexity rules, and lists each rule it fails. NIST forbids composition rules outright, so switching between policies shows how differently the standards judge the same password.
- **Personal context check.** Add your name, username, email or the site the password is for, and any of those words inside the password get flagged and costed as near-free guesses. NIST requires verifiers to block context-specific words; this is that check. The context stays local.
- **Pattern map.** The password is drawn as coloured blocks, one per pattern (dictionary word, personal info, keyboard walk, sequence, date, random), each with the bits it contributes. Characters stay masked until you reveal them.
- **Specific feedback.** Warnings and suggestions name the actual weakness ("this is similar to a commonly used password") instead of a bare pass or fail.
- **Generator.** Random passwords (length, character classes, no look-alike characters) and diceware-style passphrases from Python's `secrets` module. It shows the exact generation entropy next to the pattern estimate, checks the result against HIBP, and hands it to the analyzer in one click.
- **Batch audit.** Upload a password-manager export (Bitwarden, 1Password, Chrome, Firefox, KeePass, LastPass) or paste a list. Every entry is checked for breaches, strength and reuse, with the worst listed first and a CSV report that leaves the passwords out. Duplicates are looked up once.
- **A usable interface.** It runs as a Streamlit web app, so a user types a password into a page and sees the results, rather than running a script from a terminal.

## How the breach check works

The Have I Been Pwned lookup uses the k-anonymity range API. The password is hashed with SHA-1, and only the first five characters of that hash are sent. The API returns every breached hash that starts with those five characters, and the tool does the final match locally. The request also sets `Add-Padding`, so the response is padded with decoy rows and its size gives nothing away. The full password, and even its full hash, never leave the app. The Privacy tab shows exactly which prefix was sent.

## How the entropy estimate works

The pattern matchers and dictionaries come from [zxcvbn](https://github.com/dwolfhub/zxcvbn-python), Dropbox's strength estimator. The costing is my own. zxcvbn charges a flat 10 guesses for every character no pattern explains, which is right for human-made strings but rates a random 16-character password as crackable in about a day on one GPU. SecurePass charges log2(character pool) bits for those characters instead, then picks the cheapest combination of patterns with a short dynamic programme. Common passwords still score near zero, and random ones get the credit they are due.

The estimator only knows the patterns in its dictionaries. A human-made password built from something it does not recognise will score as if it were random, which is one reason the breach check matters.

## How it was built

- *Language:* Python 3
- *Framework:* Streamlit, for the web interface
- *External service:* Have I Been Pwned (Pwned Passwords range API, no key needed)
- *Libraries:* streamlit, requests, zxcvbn, plus `hashlib` for SHA-1 and `secrets` for generation from the standard library
- *Fonts:* Space Grotesk and JetBrains Mono (SIL Open Font License), served from `static/` (licences alongside) so the app makes no third-party font requests

The logic is split from the interface:

| File | What it holds |
| --- | --- |
| `engine.py` | Strength, entropy, policy, breach, generator and audit logic. No Streamlit. |
| `ui.py` | The CSS and HTML building blocks: verdict ring, pattern map, crack-time bars, hash view |
| `app.py` | Entry point and top navigation |
| `views/` | The three pages: analyze, generate, batch audit |
| `test_engine.py` | Tests for the engine, with the network stubbed out |

## Run it

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/streamlit run app.py
```

Tests:

```bash
.venv/bin/pip install pytest
.venv/bin/python -m pytest
```

The tests stub out the network, so they run offline.

## Privacy

Run locally, the password never leaves your machine apart from the five-character hash prefix. On a hosted copy it travels from your browser to that server over HTTPS, so audit real passwords on a local copy. That goes double for the batch audit: a vault export holds every password you own. Nothing is written to disk, uploads are capped at 5 MB, and Streamlit's usage statistics are turned off.
