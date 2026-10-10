"""SecurePass Analyzer engine: strength, entropy, policy, breach, generator and audit logic.

No Streamlit in here, so the logic can be tested and reused on its own.
"""
import csv
import hashlib
import io
import math
import re
import secrets
import string
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

import requests
from zxcvbn import feedback, matching, scoring
from zxcvbn.frequency_lists import FREQUENCY_LISTS

HIBP_RANGE = "https://api.pwnedpasswords.com/range/"
WINDOW = 72  # zxcvbn's own length cap; its matchers slow down fast past it

# (name, guesses per second, short label for the rate)
ATTACKS = [
    ("Online, rate-limited", 100 / 3600, "100 / hour"),
    ("Online, no rate limit", 10, "10 / s"),
    ("Offline, slow hash (bcrypt)", 1e4, "10K / s"),
    ("Offline, fast hash (one GPU)", 1e11, "100B / s"),
]

# (minimum effective bits, verdict), strongest first.
BANDS = [(80, "Very strong"), (64, "Strong"), (45, "Fair"), (28, "Weak"), (0, "Very weak")]

CLASSES = [
    (string.ascii_lowercase, 26),
    (string.ascii_uppercase, 26),
    (string.digits, 10),
    (string.punctuation + " ", 33),
]

# 4,096 common English words: exactly 12 bits per word for generated passphrases.
WORDS = [w for w in FREQUENCY_LISTS["english_wikipedia"] if w.isalpha() and 4 <= len(w) <= 8 and w != "https"][:4096]
AMBIGUOUS = set("Il1|O0o`'\"")

YEAR = 365.25 * 86400
UNIVERSE = 13.8e9 * YEAR


def pool_size(text):
    """Size of the character set a brute-force attacker would have to cover."""
    size = sum(n for chars, n in CLASSES if any(c in chars for c in text))
    if any(not c.isascii() or not c.isprintable() for c in text):
        size += 100  # ponytail: rough pool for non-ASCII, no standard figure exists
    return size


def context_words(text):
    """Words from free-form personal context ("Jane Doe, jdoe88, acme.com") worth matching."""
    text = text.lower()
    return sorted(set(re.findall(r"[^\W_]{3,}", text)) | set(re.findall(r"[^\W\d_]{3,}", text)))


def _cheapest_cover(password, char_bits, dictionaries):
    """Cheapest way to build the password from known patterns plus random characters.

    zxcvbn finds the patterns (dictionary words, leetspeak, keyboard walks, repeats,
    sequences, dates). The costing differs from zxcvbn: a character no pattern
    explains costs log2(pool) bits instead of zxcvbn's flat 10 guesses, so random
    passwords are not underrated. Returns (bits, sequence of matches).
    """
    n = len(password)
    ends = [[] for _ in range(n + 1)]
    # Overlapping windows keep long inputs inside zxcvbn's length cap. A window starts
    # every 36 chars so greedy matchers (repeats, walks) can chain end to end.
    # ponytail: a pattern spanning windows pays its cost once per window, so inputs
    # past 72 chars can be overrated; fine for real passwords, revisit if that changes.
    for start in range(0, n or 1, WINDOW // 2):
        for m in matching.omnimatch(password[start:start + WINDOW], dictionaries):
            m["i"] += start
            m["j"] += start
            m["bits"] = math.log2(scoring.estimate_guesses(m, password))
            ends[m["j"] + 1].append(m)

    best, back = [0.0] * (n + 1), [None] * (n + 1)
    for k in range(1, n + 1):
        best[k] = best[k - 1] + char_bits
        for m in ends[k]:
            if best[m["i"]] + m["bits"] < best[k]:
                best[k], back[k] = best[m["i"]] + m["bits"], m

    sequence, k = [], n
    while k:
        m = back[k]
        if m is None:  # random character: start or extend a brute-force run
            if sequence and sequence[-1]["pattern"] == "bruteforce":
                m = sequence.pop()
                m["i"] = k - 1
            else:
                m = {"pattern": "bruteforce", "i": k - 1, "j": k - 1}
            m["token"] = password[m["i"]:m["j"] + 1]
            m["bits"] = len(m["token"]) * char_bits
            k -= 1
        else:
            k = m["i"]
        sequence.append(m)
    return best[n], sequence[::-1]


def human_time(seconds):
    """'4 hours', '2,300 years', '3.1 million× the age of the universe'."""
    if seconds < 1:
        return "instantly"
    if seconds >= UNIVERSE:
        return f"{big(seconds / UNIVERSE)}× the age of the universe"
    if seconds >= 1000 * YEAR:
        return f"{big(seconds / YEAR)} years"
    for unit, size in (("year", YEAR), ("month", YEAR / 12), ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)):
        if seconds >= size:
            n = round(seconds / size)
            return f"{n:,} {unit}{'s' if n != 1 else ''}"


def big(n):
    """1,234 / 12 million / 3.4 billion / 10²⁷ style numbers."""
    if n < 10:
        return f"{n:.1f}"
    if n < 1e6:
        return f"{n:,.0f}"
    for size, word in ((1e12, "trillion"), (1e9, "billion"), (1e6, "million")):
        if n >= size and n < size * 1000:
            return f"{n / size:.1f} {word}"
    return "10" + str(int(math.log10(n))).translate(str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹"))


def strength(password, context=""):
    """Score a password two ways: naive charset entropy and pattern-aware entropy.

    context is free text about the user (name, username, site). Its words join the
    dictionaries, the way NIST wants context-specific words blocked.
    """
    words = context_words(context)
    dictionaries = matching.RANKED_DICTIONARIES
    if words:
        dictionaries = {**dictionaries, "user_inputs": matching.build_ranked_dict(words)}
    char_bits = math.log2(pool_size(password)) if password else 0.0
    bits, sequence = _cheapest_cover(password, char_bits, dictionaries)
    band = sum(bits >= floor for floor, _ in BANDS[1:4])  # 0-3; zxcvbn feedback goes quiet at 3
    return {
        "length": len(password),
        "naive_bits": len(password) * char_bits,
        "bits": bits,
        "sequence": sequence,
        "feedback": feedback.get_feedback(band, sequence),
        "context": words,
        "context_hits": sorted({m["matched_word"] for m in sequence if m.get("dictionary_name") == "user_inputs"}),
        "crack_times": crack_times(bits),
    }


def crack_times(bits):
    """Time to exhaust 2**bits guesses in each attack scenario."""
    guesses = 2 ** min(bits, 1000)  # past any display; the cap avoids float overflow
    return [
        {"attack": name, "rate": label, "seconds": guesses / rate, "text": human_time(guesses / rate)}
        for name, rate, label in ATTACKS
    ]


@lru_cache(maxsize=256)
def _range(prefix):
    """Every breached SHA-1 suffix sharing this 5-character prefix (k-anonymity API)."""
    r = requests.get(
        HIBP_RANGE + prefix,
        # Padding adds fake zero-count rows so the response size reveals nothing.
        headers={"Add-Padding": "true", "User-Agent": "SecurePass-Analyzer"},
        timeout=5,
    )
    r.raise_for_status()
    return r.text


def breach_check(password):
    """Times this password appears in Have I Been Pwned. Only the hash prefix is sent."""
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    rows = [line.partition(":") for line in _range(prefix).splitlines() if line]
    rows = [(h, int(c)) for h, _, c in rows if int(c)]  # count 0 = padding row
    count = next((c for h, c in rows if h == suffix), 0)
    return {"count": count, "prefix": prefix, "candidates": len(rows)}


def verdict(bits, breaches):
    """A breached password is compromised whatever its entropy. breaches=None means unknown."""
    if breaches:
        return "Compromised"
    return next(label for floor, label in BANDS if bits >= floor)


# name -> (summary, [(rule, check(password, strength, breaches) -> True / False / None)])
POLICIES = {
    "NIST SP 800-63B-4": (
        "Length plus a blocklist. NIST forbids composition rules outright.",
        [
            ("At least 15 characters", lambda p, s, b: len(p) >= 15),
            ("Not in a known breach", lambda p, s, b: None if b is None else b == 0),
            ("Not a common or predictable value", lambda p, s, b: verdict(s["bits"], 0) != "Very weak"),
            ("No context words (name, username, site)", lambda p, s, b: not s["context_hits"] if s["context"] else None),
        ],
    ),
    "PCI DSS 4.0": (
        "Requirement 8.3.6, for systems that handle card data.",
        [
            ("At least 12 characters", lambda p, s, b: len(p) >= 12),
            ("Both letters and numbers", lambda p, s, b: any(c.isalpha() for c in p) and any(c.isdigit() for c in p)),
        ],
    ),
    "Classic complexity": (
        "The upper/lower/digit/symbol rules most corporate systems still enforce.",
        [
            ("At least 12 characters", lambda p, s, b: len(p) >= 12),
            ("An upper-case letter", lambda p, s, b: any(c.isupper() for c in p)),
            ("A lower-case letter", lambda p, s, b: any(c.islower() for c in p)),
            ("A digit", lambda p, s, b: any(c.isdigit() for c in p)),
            ("A symbol", lambda p, s, b: any(not c.isalnum() for c in p)),
            ("No character three times in a row", lambda p, s, b: not re.search(r"(.)\1\1", p)),
        ],
    ),
}


def check_policy(name, password, strength_result, breaches):
    """[(rule, passed)] for one policy. passed is None when it depends on an unknown."""
    return [(rule, check(password, strength_result, breaches)) for rule, check in POLICIES[name][1]]


def generate_password(length=20, lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=False):
    """Random password with at least one character from each chosen class. Returns (password, bits)."""
    picked = [chars for (chars, _), on in zip(CLASSES, (lower, upper, digits, symbols)) if on] or [string.ascii_lowercase]
    picked = [chars.replace(" ", "") for chars in picked]  # spaces get mangled by forms
    if avoid_ambiguous:
        picked = ["".join(c for c in chars if c not in AMBIGUOUS) for chars in picked]
    alphabet = "".join(picked)
    length = max(length, len(picked))
    while True:  # rejection sampling keeps every class represented without biasing positions
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in chars for c in password) for chars in picked):
            return password, length * math.log2(len(alphabet))


def generate_passphrase(words=6, separator="-", capitalize=True, add_number=False):
    """Diceware-style passphrase from WORDS. Returns (passphrase, bits)."""
    chosen = [secrets.choice(WORDS) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    bits = words * math.log2(len(WORDS))
    if add_number:
        chosen.append(str(secrets.randbelow(100)))
        bits += math.log2(100)
    return separator.join(chosen), bits


LABEL_COLUMNS = ("name", "title", "account", "url", "login_uri", "web site", "username", "login_username")


def parse_entries(text):
    """[(label, password)] from a password-manager CSV export or a plain one-per-line list.

    Bitwarden, 1Password, Chrome, Firefox, KeePass and LastPass exports all name the
    column "password" or "login_password".
    """
    rows = list(csv.reader(io.StringIO(text)))
    header = [h.strip().lower() for h in rows[0]] if rows else []
    pw_col = next((i for i, h in enumerate(header) if h in ("password", "login_password")), None)
    if pw_col is None or len(header) < 2:
        return [(f"#{n}", line) for n, line in enumerate(text.splitlines(), 1) if line]
    label_col = next((header.index(h) for h in LABEL_COLUMNS if h in header), None)
    entries = []
    for n, row in enumerate(rows[1:], 1):
        if len(row) > pw_col and row[pw_col]:
            label = row[label_col] if label_col is not None and label_col < len(row) and row[label_col] else f"#{n}"
            entries.append((label, row[pw_col]))
    return entries


def _audit_one(password):
    s = strength(password)
    try:
        n = breach_check(password)["count"]
    except requests.RequestException:
        n = None
    return {"length": len(password), "bits": s["bits"], "breaches": n, "verdict": verdict(s["bits"], n)}


def audit(passwords, progress=None):
    """Strength, breach count and reuse count per password. Duplicates are checked once."""
    unique = list(dict.fromkeys(passwords))
    results = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_audit_one, p): p for p in unique}
        for done, future in enumerate(as_completed(futures), 1):
            results[futures[future]] = future.result()
            if progress:
                progress(done / len(unique))
    uses = Counter(passwords)
    return [{**results[p], "reused": uses[p]} for p in passwords]
