import math

import pytest

import engine

# SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
RANGE_BODY = (
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n"
    "0123456789ABCDEF0123456789ABCDEF012:0\r\n"  # padding row
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:7\r\n"
)


def test_breach_check_sends_only_prefix_and_matches_locally(monkeypatch):
    sent = []
    monkeypatch.setattr(engine, "_range", lambda prefix: sent.append(prefix) or RANGE_BODY)
    assert engine.breach_check("password") == {"count": 42, "prefix": "5BAA6", "candidates": 2}
    assert sent == ["5BAA6"]
    assert engine.breach_check("not-in-the-range")["count"] == 0


def test_patterns_cut_entropy_but_random_keeps_it():
    for weak in ["password", "Password123!", "Summer2024!", "qwertyuiopasdfgh", "aaaaaaaaaaaaaaaa"]:
        s = engine.strength(weak)
        assert s["bits"] < 28 < s["naive_bits"], (weak, s["bits"])
    random16 = engine.strength("v7#Qm2!xLp9$Tz4@")
    assert random16["bits"] == pytest.approx(random16["naive_bits"]) and random16["bits"] > 100
    assert 40 < engine.strength("correct horse battery staple")["bits"] < 70
    assert engine.strength("x" * 200)["bits"] < 45  # long inputs still get pattern-matched


def test_sequence_tiles_the_password():
    pw = "Tr0ub4dor&3 horse"
    assert "".join(m["token"] for m in engine.strength(pw)["sequence"]) == pw


def test_breach_overrides_entropy():
    assert engine.verdict(120, 3) == "Compromised"
    assert engine.verdict(120, None) == "Very strong"
    assert engine.verdict(10, 0) == "Very weak"


def test_policies():
    pw = "v7#Qm2!xLp9$Tz4@"
    s = engine.strength(pw)
    assert all(ok for _, ok in engine.check_policy("Classic complexity", pw, s, 0))
    assert [ok for _, ok in engine.check_policy("NIST SP 800-63B-4", pw, s, None)] == [True, None, True, None]
    short = "aaa1"
    assert not any(ok for _, ok in engine.check_policy("NIST SP 800-63B-4", short, engine.strength(short), 5))


def test_context_words_are_caught():
    s = engine.strength("Ananya2024!", context="Ananya Rao, arao88@example.com")
    assert s["context_hits"] == ["ananya"]
    assert engine.strength("Ananya2024!")["bits"] > s["bits"]
    nist = dict(engine.check_policy("NIST SP 800-63B-4", "Ananya2024!", s, 0))
    assert nist["No context words (name, username, site)"] is False
    assert dict(engine.check_policy("NIST SP 800-63B-4", "x", engine.strength("x"), 0))["No context words (name, username, site)"] is None


def test_generators():
    assert len(engine.WORDS) == 4096
    pw, bits = engine.generate_password(24, avoid_ambiguous=True)
    assert len(pw) == 24 and not set(pw) & engine.AMBIGUOUS
    assert any(c.isupper() for c in pw) and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)
    assert bits == pytest.approx(24 * math.log2(len(set("".join(c for c, _ in engine.CLASSES)) - engine.AMBIGUOUS - {" "})))
    phrase, bits = engine.generate_passphrase(6, separator=".", add_number=True)
    assert len(phrase.split(".")) == 7 and bits == pytest.approx(72 + math.log2(100))


def test_human_time():
    assert engine.human_time(0.5) == "instantly"
    assert engine.human_time(7200) == "2 hours"
    assert engine.human_time(5000 * engine.YEAR) == "5,000 years"
    assert engine.human_time(3e6 * engine.UNIVERSE) == "3.0 million× the age of the universe"
    assert engine.human_time(1e30 * engine.UNIVERSE) == "10³⁰× the age of the universe"


def test_parse_entries():
    bitwarden = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" \
                ',,login,GitHub,"multi\nline note",,0,https://github.com,me,hunter2,\n' \
                ",,login,,,,0,,,,\n"
    assert engine.parse_entries(bitwarden) == [("GitHub", "hunter2")]
    assert engine.parse_entries("password\n123456\n\nletmein") == [("#1", "password"), ("#2", "123456"), ("#4", "letmein")]


def test_audit_counts_reuse_and_checks_each_password_once(monkeypatch):
    sent = []
    monkeypatch.setattr(engine, "_range", lambda prefix: sent.append(prefix) or RANGE_BODY)
    rows = engine.audit(["password", "v7#Qm2!xLp9$Tz4@", "password"])
    assert [r["reused"] for r in rows] == [2, 1, 2]
    assert rows[0]["verdict"] == "Compromised" and rows[0]["breaches"] == 42
    assert len(sent) == 2
