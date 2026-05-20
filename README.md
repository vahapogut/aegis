<div align="center">
  <img src="ipeclabs-logo-light.svg" width="180" alt="Aegis by IPEC Labs"/>
  <h1>Aegis Security</h1>
  <p><strong>AI-era security scanner for LLM-generated code.</strong></p>
  <p>Detect hallucinated vulnerabilities, auth bypasses, floating promises, and risky AI-generated patterns in <b>TypeScript</b>, <b>JavaScript</b>, <b>Python</b>, and <b>Go</b> — before production.</p>

  <br/>

  <a href="#quick-start"><img src="https://img.shields.io/badge/crates.io-aegis-blue?style=for-the-badge&logo=rust" alt="crates.io"/></a>
	  <a href="#quick-start"><img src="https://img.shields.io/badge/npm-aegis--security-red?style=for-the-badge&logo=npm" alt="npm"/></a>
	  <a href="#tests"><img src="https://img.shields.io/badge/tests-28_passed-brightgreen?style=for-the-badge" alt="Tests"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=for-the-badge" alt="License"/></a>
  <a href="#rule-showcase"><img src="https://img.shields.io/badge/rules-38-red?style=for-the-badge" alt="Rules"/></a>

</div>

<br/>

> **Aegis prioritizes precision over noisy detection. We aim for zero false positives.**

---

## Quick Start

```bash
# Cargo (recommended)
cargo install aegis

# npm
npm install -g aegis-security

aegis audit .
```

No config needed. No cloud. No API keys. 100% local.

### Ignoring Violations & Files

You can ignore specific directories using a `.aegisignore` file in the root of your project.

To ignore specific rules inline, add an `aegis-ignore` comment on the violation line or the line directly above it:

```go
// aegis-ignore: ai-go-insecure-tls
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
```

Or ignore all rules for a specific block:

```typescript
// aegis-ignore: all
eval(userInput);
```

---

## Supported Languages

| Language | Rules | Status |
|----------|-------|--------|
| TypeScript / TSX | 14 | Stable |
| JavaScript / JSX | 7 | Stable |
| Python | 12 | Stable |
| Go | 5 | Stable |
| Rust | — | Planned |

More languages coming soon. Aegis uses Tree-sitter, which supports 40+ languages — the engine is ready, we just need community-driven rules.

---

## Demo

<div align="center">
  <img src="assets/demo.png" width="700" alt="Aegis Demo"/>
</div>

```bash
$ aegis audit .

[HIGH] Possible Auth Bypass. Sensitive route lacks authorization (role) checks. in auth.ts:35
    Explanation: AI often implements JWT verification but forgets to check
    if the user actually has the privileges to access the route.

[HIGH] Floating promise detected. AI often forgets to await async functions. in db.ts:12
    Explanation: Unawaited database calls may continue executing after
    the request lifecycle ends, causing race conditions.

[HIGH] Hardcoded secret detected. in config.ts:3
    Explanation: AI coding assistants frequently insert mock API keys
    which developers forget to move into environment variables.

[MEDIUM] Fake validation detected. in users.ts:7
    Explanation: AI generates if-checks that log errors but never return,
    allowing execution to continue past failed validation.

Scan Summary
────────────
HIGH:   8
MEDIUM: 1
LOW:    0

AI Risk Score: 82/100

[!] Found 9 violations
```

---

## Why Aegis Exists

AI coding assistants (Copilot, Cursor, Claude, DeepSeek) have drastically increased development speed. But they introduced a **new class of bugs** that traditional linters completely miss — because the syntax is perfectly valid. The **logic** is what's broken.

Aegis doesn't ask *"is this code vulnerable?"*
Aegis asks **"did an AI write this, and did it cut corners?"**

We use **Tree-sitter** for AST parsing and a custom **YAML rule engine** to catch these behavioral security flaws with surgical precision.

---

## Real AI-Generated Security Failures

These are actual patterns that LLMs produce daily. Aegis catches all of them.

### TypeScript

**Forgotten `await` (Race Condition)**
```typescript
app.post('/api/users', (req, res) => {
    db.save(req.body);  // ← No await. Data may never persist.
    res.send("Saved");
});
```

**Fake Validation (Auth Bypass)**
```typescript
if (!req.body.email) {
    console.log("Email missing");  // ← No return. Code continues below.
}
createUser(req.body);  // ← Runs even without email
```

**Silent Error Swallowing**
```typescript
try {
    await chargeCustomer(order);
} catch (e) {
    console.log(e);  // ← Payment fails silently.
}
```

### Python

**SQL Injection via f-string**
```python
# AI's #1 Python mistake — f-strings in SQL
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**Unsafe Pickle Deserialization (RCE)**
```python
# AI suggests pickle for everything — allows remote code execution
model = pickle.load(open("model.pkl", "rb"))
```

**DEBUG=True Left in Production**
```python
# AI generates Django/Flask boilerplate and never flips this
DEBUG = True
SECRET_KEY = "super-secret-key-12345"
```

### JavaScript

**Unsafe eval()**
```javascript
// AI sometimes uses eval for dynamic execution
const userInput = req.body.code;
eval(userInput);  // ← Remote code execution risk
```

**Hardcoded Secret**
```javascript
// AI inserts placeholder credentials that make it to production
const STRIPE_KEY = "sk_live_1234567890";
```

---

## Rule Showcase

Aegis ships with **38 precision-first rules** across TypeScript, JavaScript, Python, and Go — all tested with zero false positives.

### TypeScript Rules (16)

| Rule ID | Severity | Problem Detected |
|---------|----------|------------------|
| `ai-auth-bypass` | HIGH | JWT validated but no role/permission check |
| `ai-floating-promise` | HIGH | Unawaited async DB/Network calls |
| `ai-silent-fail` | HIGH | `catch(e) { console.log(e) }` |
| `ai-hardcoded-secret` | HIGH | Placeholder API keys left in code |
| `ai-regex-injection` | HIGH | `new RegExp(req.query.q)` |
| `ai-open-redirect` | HIGH | `res.redirect(req.query.next)` |
| `ai-insecure-fetch` | HIGH | `rejectUnauthorized: false` |
| `ai-missing-rate-limit` | HIGH | Login/OTP route without brute-force protection |
| `ai-unsafe-innerhtml` | HIGH | `innerHTML = userInput` without sanitization |
| `ai-fake-validation` | MEDIUM | Validation block that never returns/throws |
| `ai-unsafe-deserialization` | HIGH | `JSON.parse()` without error handling |
| `ai-cors-wildcard` | HIGH | CORS configured with wildcard `*` origin |
| `ai-sql-injection-js` | HIGH | SQL query built via string concatenation |
| `ai-no-timeout` | HIGH | HTTP request without timeout configured |
| `ai-path-traversal` | HIGH | File ops with unsanitized user input |
| `ai-unhandled-rejection` | MEDIUM | Promise chain without `.catch()` handler |

### JavaScript Rules (10)

| Rule ID | Severity | Problem Detected |
|---------|----------|------------------|
| `ai-hardcoded-secret-js` | HIGH | Credentials hardcoded in JS source |
| `ai-unsafe-eval` | HIGH | `eval()` or `new Function()` usage |
| `ai-no-csrf` | HIGH | POST/PUT/DELETE routes without CSRF protection |
| `ai-weak-crypto` | HIGH | MD5, SHA1, or DES algorithms detected |
| `ai-missing-auth-check` | HIGH | Route handler without auth middleware |
| `ai-nosql-injection` | HIGH | MongoDB query with raw user input |
| `ai-insecure-jwt` | HIGH | JWT with weak/none algorithm |
| `ai-exposed-stack-trace` | MEDIUM | Error handler exposes internal details |
| `ai-dangerously-set-html` | HIGH | React dangerouslySetInnerHTML without sanitization |
| `ai-missing-input-validation` | MEDIUM | Express route without body validation |

### Python Rules (14)

| Rule ID | Severity | Problem Detected |
|---------|----------|------------------|
| `ai-bare-except` | HIGH | `except:` that swallows all errors silently |
| `ai-hardcoded-secret-py` | HIGH | Credentials hardcoded in source files |
| `ai-sql-format-string` | HIGH | SQL injection via f-strings or `.format()` |
| `ai-debug-true` | HIGH | `DEBUG = True` left in Django/Flask settings |
| `ai-pickle-load` | HIGH | `pickle.load()` allows Remote Code Execution |
| `ai-hallucinated-import` | HIGH | AI-generated imports for non-existent packages |
| `ai-unsafe-yaml` | HIGH | `yaml.load()` instead of `yaml.safe_load()` |
| `ai-subprocess-shell` | HIGH | `subprocess` call with `shell=True` |
| `ai-plaintext-password` | HIGH | Password compared/stored in plaintext |
| `ai-assert-security` | HIGH | `assert` used for auth/security checks |
| `ai-requests-verify-false` | HIGH | TLS verification disabled in requests |
| `ai-default-secret-key` | HIGH | Django SECRET_KEY with placeholder value |
| `ai-broad-except` | MEDIUM | Catching `Exception` too broadly |
| `ai-django-debug-true` | HIGH | Django `DEBUG=True` in production |

### Go Rules (5)

| Rule ID | Severity | Problem Detected |
|---------|----------|------------------|
| `ai-go-sql-injection` | HIGH | SQL query built via string formatting or concatenation |
| `ai-go-insecure-tls` | HIGH | TLS verification disabled via InsecureSkipVerify |
| `ai-go-swallowed-error` | MEDIUM | Error swallowed via blank identifier `_` |
| `ai-go-command-injection` | HIGH | OS command arguments built using concatenation |
| `ai-go-hardcoded-secret` | HIGH | API keys and credentials hardcoded in Go source |

---

## Performance

Rust and Tree-sitter make Aegis blazingly fast.

```text
Scanned 12,000 LOC in 0.08s
```

Aegis adds zero noticeable overhead to your CI/CD pipeline.

Run the benchmark suite:

```bash
cargo bench
```

---

## Testing

Aegis includes a comprehensive test suite covering the engine, parser, and rule modules.

```bash
cargo test
```

Test coverage includes:
- Language detection (TypeScript, JavaScript, Python, unknown)
- AST parsing (valid and invalid syntax)
- Rule loading (YAML files, directory traversal, error handling)
- SARIF output generation
- Confidence level serialization
- File scanning with real tree-sitter queries

---

## Why not Semgrep?

"Isn't this just Semgrep?" — No. We share architectural inspiration (AST + YAML rules), but we solve a fundamentally different problem.

| | Semgrep | Aegis |
|---|---------|-------|
| **Focus** | Generic SAST | AI behavioral security |
| **Audience** | Security Engineers | Developers using AI Assistants |
| **Detects** | General vulnerabilities (SQLi, XSS) | LLM-specific failure patterns |
| **Strategy** | Broad detection | Precision-first (Zero false-positive goal) |
| **Output** | Standard warnings | Explanation Engine (*Why* the AI made this mistake) |

---

## GitHub Action

Drop Aegis into your CI/CD pipeline. It automatically audits every Pull Request and uploads SARIF results to GitHub's Security tab.

```yaml
name: Aegis Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vahapogut/aegis-action@v1
        with:
          format: 'sarif'   # Results appear in Security → Code Scanning
```

Or use it directly in any CI:

```bash
# Exit code 1 if HIGH violations found = blocks merge
aegis audit . --format sarif > aegis-results.sarif
```

---

## Output Formats

Aegis supports JSON and SARIF v2.1.0 output for easy integration with GitHub Security tab, Datadog, or custom dashboards.

```bash
aegis audit . --format text   # default, colored terminal output
aegis audit . --format json   # machine-readable with risk score
aegis audit . --format sarif  # GitHub Security tab integration
```

---

## Writing Custom Rules

Aegis rules are YAML files with Tree-sitter queries. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

```yaml
rule:
  id: "ai-your-pattern"
  language: "typescript"
  confidence: "HIGH"
  message: "Short description of the bug."
  explanation: "Why the AI does this and how to fix it."
  query: >
    (catch_clause
      body: (statement_block) @block
      (#not-match? @block "throw|return")
    )
```

---

## License

Apache-2.0. Built for the community by [IPEC Labs](mailto:info@ipeclabs.com).
