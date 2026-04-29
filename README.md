# LLM Security Scanner

One-click AWS deployment of a cost-optimized code security analyzer using self-hosted Llama 3.1 (8B) on SageMaker.

## Quick Deploy

```bash
git clone https://github.com/kdeath83/llm-security-scanner
cd llm-security-scanner
./deploy.sh
```

**Or on Windows:**
```batch
deploy.bat
```

## What Gets Deployed

| Component | Service | Cost |
|-----------|---------|------|
| LLM Engine | SageMaker Serverless (Llama 3.1 8B) | ~$200-400/mo |
| Storage | S3 | ~$5-20/mo |
| Orchestration | Lambda | ~$10-30/mo |
| **Total** | | **~$250-500/mo** |

## Usage

```bash
# Scan a Python file
./scan.sh myapp.py

# Results saved as myapp.py.security-results.json
```

## Security Vulnerabilities Detected

### Web Application Vulnerabilities

| Category | Examples |
|----------|----------|
| **Injection** | SQL injection, NoSQL injection, Command injection, LDAP injection, XPath injection |
| **XSS** | Reflected, Stored, DOM-based Cross-Site Scripting |
| **Path Traversal** | `../../../etc/passwd`, unsafe file operations |
| **SSRF** | Server-Side Request Forgery, unsafe URL fetching |
| **XXE** | XML External Entity attacks |
| **CSRF** | Missing anti-CSRF tokens |
| **Open Redirect** | Unvalidated redirect URLs |

### Authentication & Authorization

| Issue | Pattern |
|-------|---------|
| **Hardcoded credentials** | API keys, passwords, tokens in code |
| **JWT issues** | Weak signing, none algorithm, expired token validation |
| **Session management** | Predictable session IDs, missing HttpOnly/Secure flags |
| **Missing auth checks** | Admin endpoints without authorization |
| **Insecure password storage** | Plaintext, weak hashing (MD5, SHA1) |
| **Mass assignment** | Unfiltered object property assignment |

### Cryptographic Issues

| Problem | Detection |
|---------|-----------|
| **Weak algorithms** | MD5, SHA1, DES, RC4 |
| **Hardcoded keys** | Encryption keys in source |
| **Insecure randomness** | `Math.random()` for crypto |
| **Missing TLS** | HTTP instead of HTTPS |
| **Certificate validation disabled** | `verify=False` in requests |

### Infrastructure & Configuration

| Issue | Example |
|-------|---------|
| **Debug mode enabled** | `DEBUG=True` in production |
| **Verbose error messages** | Stack traces leaking to users |
| **Insecure CORS** | `Access-Control-Allow-Origin: *` |
| **Missing security headers** | No HSTS, CSP, X-Frame-Options |
| **Docker issues** | Running as root, latest tags, secrets in images |

### Data & Privacy

| Risk | Pattern |
|------|---------|
| **PII exposure** | Logging SSNs, emails, phone numbers |
| **Insecure deserialization** | `pickle.loads()`, `yaml.load(unsafe)` |
| **SQL data exposure** | `SELECT *` without filtering |
| **Missing input validation** | No sanitization on user input |
| **Information disclosure** | `.git` folder exposed, `.env` files |

### Language-Specific

| Language | Vulnerabilities |
|----------|-----------------|
| **Python** | `eval()`, `exec()`, `subprocess` without shell=False, unsafe `pickle` |
| **JavaScript/Node** | `child_process.exec` with user input, prototype pollution, path traversal in `fs` |
| **Java** | Deserialization, SQL injection with string concat, unsafe reflection |
| **Go** | `unsafe` package usage, race conditions, `filepath.Join` traversal |
| **C/C++** | Buffer overflows, use-after-free, format string bugs |

### Business Logic

| Issue | Detection |
|-------|-----------|
| **Race conditions** | TOCTOU (Time-of-check to time-of-use) |
| **IDOR** | Insecure Direct Object Reference |
| **Logic flaws** | Bypassing payment flows, negative quantity orders |
| **Missing rate limiting** | No throttling on sensitive endpoints |

## Sample Output Format

```json
{
  "vulnerabilities": [
    {
      "severity": "critical",
      "type": "SQL Injection",
      "line": 42,
      "description": "User input directly concatenated into SQL query without parameterization",
      "fix": "Use prepared statements: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
      "cwe": "CWE-89"
    },
    {
      "severity": "high", 
      "type": "Hardcoded Secret",
      "line": 15,
      "description": "AWS access key found in source code",
      "fix": "Use AWS Secrets Manager or environment variables",
      "cwe": "CWE-798"
    }
  ],
  "overall_risk_score": 75,
  "files_scanned": 1,
  "scan_duration_seconds": 3.2
}
```

## Architecture

- **SageMaker Serverless**: Llama 3.1 8B scales to zero when idle (saves 70% vs always-on)
- **Lambda**: Code parsing and LLM invocation
- **S3**: Code uploads and SARIF results
- **No OpenSearch**: Uses simple S3 + Lambda to minimize costs

## Requirements

- AWS CLI configured
- CDK installed: `npm install -g aws-cdk`
- Python 3.11+

## Next Steps

After deployment:
1. Wait 5-10 min for SageMaker endpoint
2. Test with: `./scan.sh testfile.py`
3. Integrate with CodePipeline for CI/CD

## License

MIT
