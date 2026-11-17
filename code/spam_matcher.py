"""Spam keyword detection with three exact string matching algorithms.

AOA Case Study 26: Spam Message Detection
Adarsh Singh (Roll No. 52) and Abhinav Singh (Roll No. 51), D15A

Algorithms
  1. Naive (brute force) string matching
  2. Rabin-Karp (rolling hash), for one pattern and for a whole keyword list
  3. Boyer-Moore (bad character rule + strong good suffix rule)

Usage
  python spam_matcher.py trace naive|rk|bm|all   step-by-step run on a short excerpt
  python spam_matcher.py scan 1|2            check a sample email against the keyword list
  python spam_matcher.py bench [1|2]         compare the algorithms on larger inputs
"""

import random
import sys
import textwrap
import time
from pathlib import Path

D = 256                  # radix of the rolling hash (one digit per character code)
Q_LARGE = 1_000_000_007  # large prime modulus used for real scanning
Q_DEMO = 13              # small prime used only in the hand trace


class Stats:
    """Counts the basic operations performed by one search."""

    def __init__(self):
        self.windows = 0        # alignments (shifts) of the pattern that were examined
        self.comparisons = 0    # character comparisons text[i] vs pattern[j]
        self.hash_updates = 0   # rolling hash updates (Rabin-Karp only)
        self.hash_hits = 0      # windows whose hash equalled a pattern hash
        self.spurious = 0       # hash hits that failed the character check


# ---------------------------------------------------------------- Naive

def naive_search(text, pat, st, trace=None):
    n, m = len(text), len(pat)
    hits = []
    for s in range(n - m + 1):
        j = 0
        while j < m and text[s + j] == pat[j]:
            j += 1
        used = j + 1 if j < m else m          # comparisons made at this shift
        st.windows += 1
        st.comparisons += used
        if j == m:
            hits.append(s)
        if trace is not None:
            trace.append((s, text[s:s + m], used, j))
    return hits


# ---------------------------------------------------------------- Rabin-Karp

def poly_hash(s, q):
    """Hash of s read as a base-D number, reduced mod q (Horner's rule)."""
    v = 0
    for ch in s:
        v = (D * v + ord(ch)) % q
    return v


def rabin_karp_search(text, pat, st, q=Q_LARGE, trace=None):
    n, m = len(text), len(pat)
    if m == 0 or m > n:
        return []
    h = pow(D, m - 1, q)                 # weight of the leading character
    p = poly_hash(pat, q)
    t = poly_hash(text[:m], q)
    hits = []
    for s in range(n - m + 1):
        st.windows += 1
        status = ""
        if t == p:
            st.hash_hits += 1
            j = 0
            while j < m and text[s + j] == pat[j]:
                j += 1
            st.comparisons += j + 1 if j < m else m
            if j == m:
                hits.append(s)
                status = "MATCH"
            else:
                st.spurious += 1
                status = "SPURIOUS"
        if trace is not None:
            trace.append((s, text[s:s + m], t, status))
        if s < n - m:                    # roll: drop text[s], add text[s+m]
            t = (D * (t - ord(text[s]) * h) + ord(text[s + m])) % q
            st.hash_updates += 1
    return hits


def rabin_karp_multi(text, patterns, st, q=Q_LARGE):
    """One pass over the text for the whole keyword list.

    Each pattern is fingerprinted by the hash of its first L characters, where
    L is the length of the shortest pattern. A window whose hash is in the
    table is checked against every full pattern that shares that hash.
    """
    found = {pat: [] for pat in patterns}
    n = len(text)
    L = min(len(pat) for pat in patterns)
    if L > n:
        return found
    table = {}
    for pat in patterns:
        table.setdefault(poly_hash(pat[:L], q), []).append(pat)
    h = pow(D, L - 1, q)
    t = poly_hash(text[:L], q)
    for s in range(n - L + 1):
        st.windows += 1
        cands = table.get(t)
        if cands:
            st.hash_hits += 1
            for pat in cands:
                m = len(pat)
                if s + m > n:
                    continue
                j = 0
                while j < m and text[s + j] == pat[j]:
                    j += 1
                st.comparisons += j + 1 if j < m else m
                if j == m:
                    found[pat].append(s)
                else:
                    st.spurious += 1
        if s < n - L:
            t = (D * (t - ord(text[s]) * h) + ord(text[s + L])) % q
            st.hash_updates += 1
    return found


# ---------------------------------------------------------------- Boyer-Moore

def bad_char_table(pat):
    """Last index of every character in the pattern (absent characters give -1)."""
    last = {}
    for i, ch in enumerate(pat):
        last[ch] = i
    return last


def good_suffix_table(pat):
    """Strong good suffix shifts: shift[j+1] after a mismatch at j, shift[0] after a match."""
    m = len(pat)
    shift = [0] * (m + 1)
    border = [0] * (m + 1)
    i, j = m, m + 1
    border[i] = j
    while i > 0:
        while j <= m and pat[i - 1] != pat[j - 1]:
            if shift[j] == 0:
                shift[j] = j - i
            j = border[j]
        i -= 1
        j -= 1
        border[i] = j
    j = border[0]
    for i in range(m + 1):
        if shift[i] == 0:
            shift[i] = j
        if i == j:
            j = border[j]
    return shift


def boyer_moore_search(text, pat, st, trace=None):
    n, m = len(text), len(pat)
    if m == 0 or m > n:
        return []
    last = bad_char_table(pat)
    gs = good_suffix_table(pat)
    hits = []
    s = 0
    while s <= n - m:
        st.windows += 1
        j = m - 1
        while j >= 0 and pat[j] == text[s + j]:   # compare right to left
            j -= 1
        if j < 0:
            st.comparisons += m
            hits.append(s)
            bc, g, shift = None, gs[0], gs[0]
        else:
            st.comparisons += m - j
            bc = j - last.get(text[s + j], -1)
            g = gs[j + 1]
            shift = max(bc, g)
        if trace is not None:
            used = m if j < 0 else m - j
            bad = "" if j < 0 else text[s + j]
            trace.append((s, text[s:s + m], used, j, bad, bc, g, shift))
        s += shift
    return hits


# ---------------------------------------------------------------- sample data

KEYWORDS = [
    "urgent", "winner", "congratulations", "lottery", "cash prize",
    "claim your prize", "click here", "bank account", "verify",
    "limited time", "act now", "100% free", "free",
]

EMAILS = {
    "1": ("URGENT: You are a WINNER!",
          "URGENT: You are a WINNER! Dear customer, congratulations! Your email ID was "
          "picked in our online lottery and you have won a cash prize of Rs 5,00,000. "
          "To claim your prize, click here and verify your bank account details within "
          "24 hours. This is a limited time offer, so act now. Registration is 100% free "
          "and there are no hidden charges."),
    "2": ("AOA lab moved to Friday",
          "Hi all, the AOA lab session on string matching has been moved to Friday, "
          "10 am, in Lab 3. Please bring your laptops with the Naive, Rabin-Karp and "
          "Boyer-Moore programs ready. Feel free to mail me if you have any doubts "
          "before the session. Regards, Lab Assistant"),
}

SPAM_THRESHOLD = 3   # distinct keywords needed to flag a message as spam

EXCERPT = "get free offers here"
EXCERPT_PAT = "free"

CORPUS_PIECES = [
    EMAILS["1"][1], EMAILS["2"][1],
    "Your account has been suspended. Update your details today to avoid closure "
    "of your account. This is an automated message, do not reply.",
    "Team, please find attached the minutes of yesterday's meeting. The next review "
    "is on Monday and each group should present the progress of their case study.",
    "Exclusive deal for you! Buy one get one free on all orders placed before midnight. "
    "Use the coupon at checkout and save big on your next purchase.",
    "Dear student, the semester fee receipt is now available on the portal. Contact "
    "the accounts office if the amount shown does not match your records.",
    "Earn extra cash from home! Work just two hours a day and make money fast. "
    "No experience needed, no investment, guaranteed income every week.",
    "Reminder: the library will remain closed on Saturday for maintenance. Books "
    "due on that day can be returned on Monday without any fine.",
]

MORE_KEYWORDS = [
    "act immediately", "additional income", "affordable", "all natural", "amazing",
    "apply now", "as seen on", "bargain", "being a member", "best price", "big bucks",
    "billion dollars", "buy direct", "call now", "cancel at any time", "cash bonus",
    "certified", "cheap", "click below", "credit card", "dear friend", "discount",
    "do it today", "double your income", "earn extra cash", "earn money", "easy terms",
    "eliminate debt", "exclusive deal", "expires today", "extra income", "fast cash",
    "for only", "free access", "free gift", "free money", "free trial", "full refund",
    "get it now", "get paid", "gift card", "guaranteed", "hidden assets", "huge discount",
    "important information", "income from home", "increase sales", "inheritance",
    "instant access", "investment opportunity", "lose weight", "lowest price", "luxury",
    "make money", "million dollars", "miracle", "money back", "no catch", "no cost",
    "no credit check", "no fees", "no hidden charges", "offer expires", "once in a lifetime",
    "online pharmacy", "order now", "password", "pre-approved", "pure profit", "refinance",
    "reward", "risk free", "satisfaction guaranteed", "save big", "special offer",
    "special promotion", "suspended", "this is not spam", "unclaimed", "update your details",
    "verify your account", "wire transfer", "work from home", "you are a winner",
    "you have been selected", "your account", "50% off",
]


# ---------------------------------------------------------------- helpers

def show(s):
    return '"' + s + '"'


def rule(ch="-", width=92):
    print(ch * width)


def run_trace_all():
    text, pat = EXCERPT, EXCERPT_PAT
    n, m, q = len(text), len(pat), Q_DEMO
    h, p = pow(D, m - 1, q), poly_hash(pat, q)
    last, gs = bad_char_table(pat), good_suffix_table(pat)
    print(f'Text T = {show(text)}  (n = {n})      Pattern P = {show(pat)}  (m = {m})')
    print(f"Rabin-Karp : d = {D}, q = {q}, h = {D}^{m - 1} mod {q} = {h}, p = hash({show(pat)}) = {p}")
    print("Boyer-Moore: last[] = " + ", ".join(f"{c}:{i}" for c, i in last.items())
          + ", others:-1    good suffix gs[0..4] = " + " ".join(str(v) for v in gs))
    rule("=")
    st_n, st_r, st_b = Stats(), Stats(), Stats()
    rows_n, rows_r, rows_b = [], [], []
    naive_search(text, pat, st_n, rows_n)
    rabin_karp_search(text, pat, st_r, q, rows_r)
    boyer_moore_search(text, pat, st_b, rows_b)
    bm = {r[0]: r for r in rows_b}
    print(f"{'':12}| {'NAIVE':<20}| {'RABIN-KARP':<22}| BOYER-MOORE")
    print(f"{'  s  window':<12}| {'cmp  result':<20}| {'t(s)  result':<22}| cmp  bad char  good suf  shift")
    rule()
    for (s, win, used, j), (_, _, t, status) in zip(rows_n, rows_r):
        nres = "MATCH" if j == m else f"fail at j={j}"
        rres = {"MATCH": "hit, MATCH", "SPURIOUS": "hit, SPURIOUS"}.get(status, "-")
        if s in bm:
            _, _, bused, _, _, bc, g, shift = bm[s]
            bres = f" {bused:>3}  {'-' if bc is None else bc:>8}  {g:>8}  {shift:>5}"
        else:
            bres = "   skipped"
        print(f"{s:>3}  {show(win):<7}|{used:>4}  {nres:<15}|{t:>5}  {rres:<16}|{bres}")
    rule()
    upd = f"({st_r.hash_updates} updates)"
    spu = f"({st_r.spurious} spurious)"
    print(f"{'windows':<12}|{st_n.windows:>4}{'':<17}|{st_r.windows:>5}  {upd:<16}| {st_b.windows:>3}")
    print(f"{'comparisons':<12}|{st_n.comparisons:>4}{'':<17}|{st_r.comparisons:>5}  {spu:<16}| {st_b.comparisons:>3}")
    print("All three report the keyword at shift 4.")


def run_trace(which):
    if which == "all":
        run_trace_all()
        return
    text, pat = EXCERPT, EXCERPT_PAT
    n, m = len(text), len(pat)
    print(f'Text T    = {show(text)}   n = {n}')
    print(f'Pattern P = {show(pat)}   m = {m}')
    rule("=")
    st = Stats()
    rows = []
    if which == "naive":
        print("NAIVE STRING MATCHING (left to right, shift by 1 every time)")
        rule()
        print(f"{'s':>3}  {'window':<8}{'comparisons':>12}   result")
        hits = naive_search(text, pat, st, rows)
        for s, win, used, j in rows:
            res = "MATCH" if j == m else f"mismatch at j = {j} ({show(win[j])} vs {show(pat[j])})"
            print(f"{s:>3}  {show(win):<8}{used:>12}   {res}")
    elif which == "rk":
        q = Q_DEMO
        h = pow(D, m - 1, q)
        p = poly_hash(pat, q)
        print(f"RABIN-KARP (d = {D}, q = {q})")
        print(f"h = d^(m-1) mod q = {D}^{m - 1} mod {q} = {h}")
        print(f"p = hash({show(pat)}) = {p}")
        print("ASCII codes: " + "  ".join(f"{'space' if c == ' ' else c}={ord(c)}" for c in sorted(set(text))))
        rule()
        print(f"{'s':>3}  {'window':<8}{'t(s)':>6}   {'t(s) = p ?':<11} result")
        hits = rabin_karp_search(text, pat, st, q, rows)
        for s, win, t, status in rows:
            eq = "yes" if t == p else "no"
            res = {"MATCH": "verified, MATCH", "SPURIOUS": "verified, SPURIOUS HIT"}.get(status, "skip")
            print(f"{s:>3}  {show(win):<8}{t:>6}   {eq:<11} {res}")
    else:
        last = bad_char_table(pat)
        gs = good_suffix_table(pat)
        print("BOYER-MOORE (compare right to left, shift = max(bad character, good suffix))")
        print("bad character table : " + ", ".join(f"{show(c)} -> {i}" for c, i in last.items())
              + ", any other -> -1")
        print("good suffix shift[] : " + ", ".join(f"[{i}]={v}" for i, v in enumerate(gs)))
        rule()
        print(f"{'s':>3}  {'window':<8}{'comparisons':>12}  {'mismatch':<14}{'bad char':>9}"
              f"{'good suf':>9}{'shift':>7}")
        hits = boyer_moore_search(text, pat, st, rows)
        for s, win, used, j, bad, bc, g, shift in rows:
            mis = "none (MATCH)" if j < 0 else f"j={j}, {show(bad)}"
            bcs = "-" if bc is None else str(bc)
            print(f"{s:>3}  {show(win):<8}{used:>12}  {mis:<14}{bcs:>9}{g:>9}{shift:>7}")
    rule()
    extra = f", hash updates = {st.hash_updates}, spurious hits = {st.spurious}" if which == "rk" else ""
    print(f"windows examined = {st.windows}, character comparisons = {st.comparisons}{extra}")
    print(f"pattern found at shift(s): {hits}")


def run_scan(key):
    subject, body = EMAILS[key]
    text = body.lower()                    # case-insensitive matching
    n = len(text)
    print(f"Message {key}: {show(subject)}")
    for line in textwrap.wrap(body, 88):
        print("  " + line)
    print(f"After lower-casing: n = {n} characters.  Keyword list: k = {len(KEYWORDS)} patterns")
    rule("=")

    results = {}
    timings = {}
    stats = {}
    for name, fn in (("Naive (k passes)", naive_search),
                     ("Rabin-Karp (k passes)", rabin_karp_search),
                     ("Boyer-Moore (k passes)", boyer_moore_search)):
        st = Stats()
        t0 = time.perf_counter()
        found = {pat: fn(text, pat, st) for pat in KEYWORDS}
        timings[name] = (time.perf_counter() - t0) * 1000
        results[name], stats[name] = found, st
    st = Stats()
    t0 = time.perf_counter()
    found = rabin_karp_multi(text, KEYWORDS, st)
    name = "Rabin-Karp multi (1 pass)"
    timings[name] = (time.perf_counter() - t0) * 1000
    results[name], stats[name] = found, st

    ref = results["Naive (k passes)"]
    print(f"{'keyword':<20}{'m':>3}  {'count':>5}  positions (0-based index in the message)")
    rule()
    for pat in KEYWORDS:
        pos = ref[pat]
        if pos:
            print(f"{pat:<20}{len(pat):>3}  {len(pos):>5}  {pos}")
    missing = [pat for pat in KEYWORDS if not ref[pat]]
    if missing:
        for line in textwrap.wrap("not found: " + ", ".join(missing), 90):
            print(line)
    rule()
    print(f"{'algorithm':<27}{'windows':>9}{'char comparisons':>18}{'hash updates':>14}{'time (ms)':>11}")
    for name in results:
        s = stats[name]
        hu = str(s.hash_updates) if "Rabin" in name else "-"
        print(f"{name:<27}{s.windows:>9}{s.comparisons:>18}{hu:>14}{timings[name]:>11.3f}")
    rule()
    same = all(results[name] == ref for name in results)
    print(f"All four runs report identical positions: {'YES' if same else 'NO'}")
    distinct = [pat for pat in KEYWORDS if ref[pat]]
    total = sum(len(ref[pat]) for pat in KEYWORDS)
    verdict = "SPAM" if len(distinct) >= SPAM_THRESHOLD else "NOT SPAM"
    print(f"Distinct keywords found = {len(distinct)} of {len(KEYWORDS)}, total occurrences = {total}")
    print(f"Rule: SPAM if distinct keywords >= {SPAM_THRESHOLD}   ->   VERDICT: {verdict}")
