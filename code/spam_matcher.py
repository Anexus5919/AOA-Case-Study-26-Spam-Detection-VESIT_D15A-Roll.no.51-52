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
