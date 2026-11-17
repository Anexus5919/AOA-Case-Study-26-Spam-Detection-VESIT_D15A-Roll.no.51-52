# AOA Case Study 26: Spam Message Detection

Analysis of Algorithms (AOA), Continuous Assessment 2 (CA2) group case study.
Vivekanand Education Society's Institute of Technology (VESIT), Chembur, Mumbai.

| Student Name  | Roll No. | Class |
|---------------|----------|-------|
| Adarsh Singh  | 52       | D15A  |
| Abhinav Singh | 51       | D15A  |

**Report:** [AOA_CA2_Case_Study_26_Spam_Message_Detection_Roll_51_52.pdf](AOA_CA2_Case_Study_26_Spam_Message_Detection_Roll_51_52.pdf)

## Problem

An email service keeps a list of suspicious words and phrases ("winner", "claim your prize",
"verify your bank account" and so on) and has to find them quickly inside every incoming
message. A message that contains several of them is flagged as spam. We compare three exact
string matching algorithms for this job:

- **Naive (brute force):** tries every shift and compares left to right.
- **Rabin-Karp:** compares rolling hash values and only checks characters on a hash match. We
  also implemented a one-pass multi-pattern version that checks the whole keyword list at once.
- **Boyer-Moore:** compares right to left and skips ahead using the bad character and strong
  good suffix rules.

## Running the program

Python 3.12, standard library only.

```
cd code
python spam_matcher.py trace all     # step-by-step working of all three on "get free offers here"
python spam_matcher.py trace naive   # also: trace rk, trace bm
python spam_matcher.py scan 1        # spam sample email, verdict SPAM
python spam_matcher.py scan 2        # normal sample email, verdict NOT SPAM
python spam_matcher.py bench 1       # one keyword under four input conditions
python spam_matcher.py bench 2       # whole keyword list, k = 13 and k = 100
```

Every run also writes its output to `code/results/`. The files in that folder are the exact runs
shown in the report and in `screenshots/`.

## Measured results

100,000-character email corpus, best of 3 runs on a Windows 11 laptop (from `code/results/bench_1.txt` and `bench_2.txt`):

| Input condition | Naive | Rabin-Karp | Boyer-Moore |
|---|---|---|---|
| Short keyword "free" (m = 4) | 11.9 ms | 23.8 ms | 7.3 ms |
| Long keyword "verify your bank account" (m = 24) | 11.7 ms | 22.9 ms | 1.7 ms |
| Repetitive text, keyword absent | 47.6 ms | 23.1 ms | 23.4 ms |
| Repetitive text, keyword everywhere | 48.7 ms | 74.2 ms | 51.3 ms |

| Whole keyword list | Naive (k passes) | Boyer-Moore (k passes) | Rabin-Karp multi (1 pass) |
|---|---|---|---|
| k = 13 keywords | 158.5 ms | 53.1 ms | 26.2 ms |
| k = 100 keywords | 1257.2 ms | 340.4 ms | 28.9 ms |

Boyer-Moore is the fastest for a single keyword. For a growing list of keywords, one-pass
Rabin-Karp is the most suitable, because its cost depends on the message length and hardly at
all on the number of keywords. The full analysis, hand traces and complexity derivations are in
the report.

## Repository layout

```
code/spam_matcher.py   all three algorithms, sample data and the trace, scan and bench modes
code/results/          saved output of every run used in the report
screenshots/           console screenshots of those runs
AOA_CA2_Case_Study_26_Spam_Message_Detection_Roll_51_52.pdf   the case study report
```
