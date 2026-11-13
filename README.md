<p align="center">
  <img src="assets/banner.svg" alt="promptguard banner" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-f43f5e?style=for-the-badge" alt="python">
  <img src="https://img.shields.io/badge/dependencies-zero-f59e0b?style=for-the-badge" alt="zero deps">
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" alt="MIT">
</p>

**promptguard** scans text and files for common prompt-injection tricks, so you can check untrusted content (web pages, emails, uploaded docs) before feeding it to an LLM or agent.

## What it catches

| Severity | Examples |
|----------|----------|
| high | "ignore previous instructions", "reveal your system prompt", role hijacks, "send ... to https://..." |
| med | fake `<system>` tags, "developer mode", "do not tell the user", long base64 blobs |
| low | invisible Unicode characters (zero-width, bidi override) |

## Usage

```bash
python promptguard.py email.txt page.md      # scan files
cat untrusted.txt | python promptguard.py    # scan stdin
python promptguard.py doc.txt --json         # JSON for pipelines
```

Sample output:

```
doc.txt  risk score: 7
  HIGH line 3    override-instructions  'Ignore previous instructions'
  MED  line 9    fake-system-tag        '<system>'
```

## Use it in CI

Exit code is `1` when any **high** severity finding exists, `0` otherwise.

```bash
python promptguard.py inputs/*.txt || echo "suspicious content found"
```

## Honest limits

This is a fast pattern matcher, not a guarantee. Attackers can rephrase. Treat it as a cheap first filter, and keep real defenses (least privilege, human approval for risky actions) in place.

## Add your own rules

Edit the `RULES` list at the top of `promptguard.py`: `(severity, name, regex)`.

## License

MIT
