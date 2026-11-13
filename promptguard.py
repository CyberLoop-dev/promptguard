#!/usr/bin/env python3
"""promptguard: scan text and files for prompt-injection patterns."""
import argparse
import json
import re
import sys

RULES = [
    ("high", "override-instructions",
     r"ignore (all |any |the )?(previous|prior|above|earlier) (instructions|prompts?|rules)"),
    ("high", "override-instructions",
     r"disregard (all |any |the )?(previous|prior|above|system) (instructions|prompts?|rules)"),
    ("high", "reveal-system-prompt",
     r"(reveal|show|print|repeat|leak) (me )?(your |the )?(system|hidden|initial) (prompt|instructions|message)"),
    ("high", "exfiltration",
     r"(send|post|upload|forward) .{0,60}(to|at) https?://"),
    ("high", "role-hijack",
     r"you are now (a |an |in )?[a-z ]{0,30}(mode|dan|jailbroken|unfiltered)"),
    ("med", "developer-mode", r"(developer|debug|god|sudo) mode"),
    ("med", "fake-system-tag",
     r"<\s*/?\s*(system|assistant|instructions?)\s*>|\[\s*(system|inst)\s*\]"),
    ("med", "do-not-tell", r"(do not|don't|never) (tell|inform|mention to) (the )?user"),
    ("med", "encoded-payload", r"[A-Za-z0-9+/]{80,}={0,2}"),
    ("low", "hidden-chars", "[\u200b\u200c\u200d\u2060\ufeff\u202e]"),
]
WEIGHT = {"high": 5, "med": 2, "low": 1}
COMPILED = [(sev, name, re.compile(rx, re.I)) for sev, name, rx in RULES]
COLORS = {"high": "\033[91m", "med": "\033[93m", "low": "\033[96m"}


def scan(text):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for sev, name, rx in COMPILED:
            m = rx.search(line)
            if m:
                snippet = m.group(0)
                if name == "hidden-chars":
                    snippet = "U+%04X" % ord(snippet[0])
                findings.append({"line": lineno, "severity": sev,
                                 "rule": name, "match": snippet[:80]})
    return findings


def main():
    ap = argparse.ArgumentParser(description="Scan for prompt-injection patterns.")
    ap.add_argument("files", nargs="*", help="files to scan (default: stdin)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()

    sources = []
    if a.files:
        for p in a.files:
            with open(p, encoding="utf-8", errors="replace") as f:
                sources.append((p, f.read()))
    else:
        sources.append(("<stdin>", sys.stdin.read()))

    report, any_high = [], False
    for name, text in sources:
        f = scan(text)
        score = sum(WEIGHT[x["severity"]] for x in f)
        any_high = any_high or any(x["severity"] == "high" for x in f)
        report.append({"source": name, "score": score, "findings": f})

    if a.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for r in report:
            print(f"\n{r['source']}  risk score: {r['score']}")
            if not r["findings"]:
                print("  \033[92mclean\033[0m")
            for x in r["findings"]:
                c = COLORS[x["severity"]]
                print(f"  {c}{x['severity'].upper():4}\033[0m line {x['line']:<4} "
                      f"{x['rule']:<22} {x['match']!r}")
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()
