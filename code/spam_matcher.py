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
