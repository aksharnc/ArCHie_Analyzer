# Contributing to ArCHie Analyzer

Thank you for your interest in contributing! This document provides guidelines for reporting bugs, suggesting features, and submitting code changes.

---

## 🐛 Reporting Bugs

If you find a bug, please open an issue with:

1. **Clear title** — what broke and where
2. **Steps to reproduce** — exact commands and IOCs tested
3. **Expected vs. actual behavior** — what should happen, what actually happened
4. **Environment** — Python version, OS, which API sources were enabled
5. **Logs** — relevant output from `output/logs/` if available

Example:
```
Title: VirusTotal timeout on bulk analysis with 50+ IOCs

Steps:
1. Run: python analyzer.py -f large_iocs.txt
2. Expected: Process all IOCs
3. Actual: Request times out after 30 IOCs

Environment: Python 3.11, Windows 11, VirusTotal key configured
```

---

## 💡 Suggesting Features

Open an issue with:

1. **Feature title** — concise description
2. **Use case** — why is this useful for SOC/VAPT teams?
3. **Proposed solution** — how would you like it to work?
4. **Alternatives** — other ways to solve this?

Example:
```
Title: Support CIDR range analysis

Use case: SOC analysts need to check multiple IPs in a /24 subnet quickly.

Proposed: Accept CIDR notation (192.168.1.0/24) and bulk-analyze each IP,
producing a summary table of all verdicts.
```

---

## 🔧 Submitting Code Changes

### Before you start

1. **Check existing issues** — avoid duplicate work
2. **Discuss large changes** — open an issue first if it's major
3. **Fork the repo** — create your own branch
4. **Test your changes** — run against sample IOCs before submitting

### Code style

- **Python**: follow PEP 8
  - 4-space indents, max 88 chars per line
  - Use type hints for function signatures
  - Add docstrings to all functions

- **No hardcoded secrets** — credentials always go in `.env`
- **Comments**: explain *why*, not *what* (code is self-documenting)

### Branch naming

```
feature/short-description      # New feature
fix/issue-title-slug           # Bug fix
docs/update-section            # Documentation update
refactor/module-cleanup        # Code refactoring
```

### Pull Request checklist

- [ ] Branch is up-to-date with `main`
- [ ] Changes tested locally against sample IOCs
- [ ] No hardcoded credentials or API keys
- [ ] `.env` is NOT tracked
- [ ] Docstrings and type hints added
- [ ] README updated if behavior changes

### PR description template

```
## Description
Brief description of what this change does.

## Type of change
- [ ] Feature
- [ ] Bug fix
- [ ] Breaking change (requires version bump)
- [ ] Documentation update

## Testing
Describe how you tested this. Include sample IOCs used.

## Screenshots (if UI changes)
Paste terminal output or screenshots showing before/after.

## Related issues
Closes #123
```

---

## 📦 Adding a New API Source

Steps to integrate a new threat intel API (e.g., Shodan):

1. **Create `apis/shodan.py`** with functions:
   ```python
   def analyze_ip(ip: str, proxies: dict) -> dict:
       """Return {"source": "Shodan", "verdict": "...", "data": {...}, ...}"""
       ...
   
   def analyze_domain(domain: str, proxies: dict) -> dict:
       """Return {"source": "Shodan", "verdict": "...", "data": {...}, ...}"""
       ...
   ```

2. **Add API key to `.env.example`**:
   ```
   # Shodan — https://www.shodan.io/
   # Free: 1 query/month | Paid: unlimited
   SHODAN_KEY=
   ```

3. **Update `analyzer.py`** `_build_dispatch()`:
   ```python
   from apis import shodan
   
   "ipv4": [
       ...,
       (shodan.analyze_ip, "Shodan"),
   ],
   "domain": [
       ...,
       (shodan.analyze_domain, "Shodan"),
   ],
   ```

4. **Write tests** against sample IOCs
5. **Update README** under "API Sources" table

---

## 📝 Updating Documentation

- **README.md**: Update when features change or new sources are added
- **Docstrings**: Keep function documentation in sync with code
- **Changelog**: Document all changes in the appropriate version section

---

## ❓ Questions?

- Open an issue as a **question** (GitHub supports this)
- Keep discussions focused on the topic

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License (see [LICENSE](LICENSE)).

---

Thank you for improving ArCHie Analyzer! 🛡️
