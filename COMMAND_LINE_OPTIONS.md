# Command-Line Options Guide

Complete guide to all command-line options for the XML secrets scanner tools.

---

## Table of Contents

1. [Available Tools](#available-tools)
2. [Common Options](#common-options)
3. [Filtering Options](#filtering-options)
4. [Output Options](#output-options)
5. [Performance Options](#performance-options)
6. [Examples](#examples)

---

## Available Tools

### 1. `scan_with_plugins.py` - Line-Based Scanner (Fast)

**Best for:** Large repositories, single-line XML

```bash
python3 scan_with_plugins.py <directory> [options]
```

**Characteristics:**
- ⚡ Fast - processes line-by-line
- ✓ Handles single-line XML perfectly
- ✗ May miss multi-line XML secrets
- ✓ Works with XML, YAML, properties, config files

---

### 2. `scan_xml_with_context.py` - Context-Aware Scanner (Full-Featured)

**Best for:** XML files with multi-line values, detailed analysis

```bash
python3 scan_xml_with_context.py <path> [options]
```

**Characteristics:**
- ✓ Parses XML structure (handles multi-line)
- ✓ Provides full element paths (e.g., `/config/database/password`)
- ✓ Shows parent element context
- ✓ Normalizes XML before scanning
- Slower but more accurate for complex XML

---

## Common Options

### Positional Arguments

#### `directory` or `path`
The directory or file to scan.

```bash
# Scan a directory
python3 scan_with_plugins.py /path/to/repo

# Scan a specific file (scan_xml_with_context only)
python3 scan_xml_with_context.py /path/to/file.xml
```

---

### Output Options

#### `--output OUTPUT` or `-o OUTPUT`
Save results to a JSON file instead of printing to stdout.

```bash
python3 scan_with_plugins.py /repo --output results.json
```

**JSON Output Format:**
```json
{
  "scan_directory": "/repo",
  "total_secrets_found": 5,
  "secrets": [
    {
      "file": "config.xml",
      "line_number": 10,
      "type": "XML Password",
      "secret": "MyS3cur3P@ss!",
      "line_content": "<password>MyS3cur3P@ss!</password>"
    }
  ]
}
```

**⚠️ IMPORTANT:** Output files contain actual secret values! Always use `.gitignore` to prevent committing them.

**Best Practice:**
```bash
# Store results outside the repository
python3 scan_with_plugins.py /repo \
  --output ~/security-audits/scan-$(date +%Y%m%d).json
```

---

#### `--extensions EXTENSIONS [EXTENSIONS ...]` or `-e EXTENSIONS [...]`
Specify which file extensions to scan.

**Default (scan_with_plugins.py):** `.xml .config .conf .properties .yaml .yml`
**Default (scan_xml_with_context.py):** `.xml .config`

```bash
# Scan only XML files
python3 scan_with_plugins.py /repo --extensions .xml

# Scan XML and YAML files
python3 scan_with_plugins.py /repo --extensions .xml .yaml .yml

# Scan all config-related files
python3 scan_with_plugins.py /repo \
  --extensions .xml .config .conf .properties .yaml .yml .json
```

**Use Case:**
- Focus on specific file types to speed up scans
- Avoid scanning irrelevant files

---

## Filtering Options

Filtering options use **regex patterns** to include or exclude specific XML elements and attributes.

### Entity/Element Filtering

#### `--include-entities INCLUDE_ENTITIES [INCLUDE_ENTITIES ...]`
**Include ONLY** XML elements matching these regex patterns.

```bash
# Only scan elements with "prod" or "production" in the name
python3 scan_with_plugins.py /repo \
  --include-entities "prod_.*" "production_.*"

# Result:
# ✓ <prod_password>secret</prod_password>         - DETECTED
# ✓ <production_api_key>key</production_api_key>  - DETECTED
# ✗ <test_password>secret</test_password>         - IGNORED (not in include list)
# ✗ <password>secret</password>                   - DETECTED (matches default patterns)
```

**Important:** Elements matching default patterns (like `<password>`, `<secret>`, `<api_key>`) are ALWAYS scanned, even if not in include list.

---

#### `--exclude-entities EXCLUDE_ENTITIES [EXCLUDE_ENTITIES ...]`
**Exclude** XML elements matching these regex patterns.

```bash
# Exclude all test/dev/example elements
python3 scan_with_plugins.py /repo \
  --exclude-entities "test_.*" "dev_.*" "example_.*"

# Result:
# ✓ <password>secret</password>           - DETECTED
# ✓ <prod_password>secret</prod_password> - DETECTED
# ✗ <test_password>secret</test_password> - EXCLUDED
# ✗ <dev_secret>secret</dev_secret>       - EXCLUDED
```

---

### Attribute Filtering

#### `--include-attributes INCLUDE_ATTRIBUTES [INCLUDE_ATTRIBUTES ...]`
**Include ONLY** XML attributes matching these regex patterns.

```bash
# Only scan attributes with "password" or "secret"
python3 scan_with_plugins.py /repo \
  --include-attributes ".*password.*" ".*secret.*"

# Result:
# ✓ <server password="secret">          - DETECTED
# ✓ <db master_password="pwd">          - DETECTED
# ✗ <server hostname="localhost">       - IGNORED
```

---

#### `--exclude-attributes EXCLUDE_ATTRIBUTES [EXCLUDE_ATTRIBUTES ...]`
**Exclude** XML attributes matching these regex patterns.

```bash
# Exclude test-related attributes
python3 scan_with_plugins.py /repo \
  --exclude-attributes "test_.*" "example_.*"

# Result:
# ✓ password="secret"                   - DETECTED
# ✗ test_password="secret"              - EXCLUDED
```

---

### The `--prod-only` Flag (Shorthand)

A convenient shorthand for common production-only filtering.

```bash
python3 scan_with_plugins.py /repo --prod-only
```

**Equivalent to:**
```bash
python3 scan_with_plugins.py /repo \
  --include-entities "prod_.*" "production_.*" "live_.*" \
  --exclude-entities "test_.*" "dev_.*" "development_.*" \
                      "example_.*" "sample_.*" "demo_.*" \
  --min-length 6
```

**What it does:**
- ✓ Includes: `prod_*`, `production_*`, `live_*` elements
- ✓ Always includes: generic `<password>`, `<secret>`, `<api_key>` tags
- ✗ Excludes: `test_*`, `dev_*`, `example_*`, `sample_*`, `demo_*` elements
- Sets minimum password length to 6 characters

**Use Cases:**
```bash
# Scan only production secrets in a mixed config file
python3 scan_with_plugins.py /repo --prod-only --output prod-secrets.json

# Find production secrets that may have been committed
python3 scan_with_plugins.py . --prod-only
```

**Example Detection:**
```xml
<!-- With --prod-only -->
<config>
    <!-- DETECTED -->
    <password>ProductionSecret123!</password>
    <prod_password>ProdSecret!</prod_password>
    <live_api_key>LiveKey123!</live_api_key>

    <!-- EXCLUDED -->
    <test_password>TestSecret!</test_password>
    <dev_secret>DevSecret!</dev_secret>
    <example_password>example</example_password>
</config>
```

---

### `--min-length MIN_LENGTH`
Set the minimum length for detected passwords.

**Default:** 4 characters
**With `--prod-only`:** 6 characters

```bash
# Only detect passwords 8+ characters
python3 scan_with_plugins.py /repo --min-length 8

# Result:
# ✓ <password>MyS3cur3P@ss!</password>  - DETECTED (14 chars)
# ✗ <password>short</password>          - IGNORED (5 chars)
```

**Use Cases:**
- Reduce false positives from short test values
- Focus on complex passwords
- Compliance requirements (e.g., "passwords must be 12+ chars")

**Recommendation:** Use 6-8 for production scans to avoid noise.

---

## Detection Control Options

### `--disable-unix-crypt`
Disable Unix crypt hash detection entirely.

```bash
python3 scan_with_plugins.py /repo --disable-unix-crypt
```

**What it does:**
- Disables detection of bcrypt, SHA-512, SHA-256, MD5, yescrypt hashes
- Only detects plaintext passwords/secrets
- Faster scanning

**Use Cases:**
- You only care about plaintext secrets
- Crypt hashes are expected (e.g., in password database dumps)
- Speed up scans

**Default Behavior (without this flag):**
- ✓ Detects bcrypt: `$2a$12$...`
- ✓ Detects SHA-512: `$6$...`
- ✓ Detects SHA-256: `$5$...`
- ✓ Detects MD5: `$1$...`
- ✗ DES disabled by default (too many false positives)

---

### `--no-normalize` (scan_xml_with_context.py only)
Skip XML normalization for faster scanning.

```bash
python3 scan_xml_with_context.py /repo --no-normalize
```

**What it does:**
- Skips converting multi-line XML to single-line format
- Faster but may miss secrets split across lines

**Use Cases:**
- You know your XML is single-line
- Speed is critical
- Quick scans

**Trade-off:**
```xml
<!-- Without --no-normalize: DETECTED -->
<password>
    MyMultiLineSecret123!
</password>

<!-- With --no-normalize: MAY BE MISSED -->
<password>
    MyMultiLineSecret123!
</password>
```

**Recommendation:** Omit this flag (use normalization) unless you're certain XML is single-line.

---

## Regex Pattern Syntax

All `--include-*` and `--exclude-*` options use **Python regex** syntax.

### Common Patterns

| Pattern | Matches | Example |
|---------|---------|---------|
| `prod_.*` | Anything starting with "prod_" | `prod_password`, `prod_api_key` |
| `.*_prod` | Anything ending with "_prod" | `database_prod`, `api_prod` |
| `.*prod.*` | Anything containing "prod" | `production`, `prod_db`, `db_prod` |
| `prod\|live` | "prod" OR "live" | `prod_password`, `live_password` |
| `(prod\|live)_.*` | Starts with "prod_" or "live_" | `prod_secret`, `live_api_key` |
| `test_.*\|dev_.*` | Starts with "test_" OR "dev_" | `test_password`, `dev_secret` |

### Examples

```bash
# Match prod, production, live
--include-entities "prod_.*" "production_.*" "live_.*"

# Match anything ending in _password
--include-entities ".*_password"

# Exclude test, dev, demo
--exclude-entities "test_.*" "dev_.*" "demo_.*"

# Match specific patterns
--include-entities "database_(prod|production)" "api_(live|prod)"
```

---

## Examples

### Basic Scanning

#### 1. Scan a directory with default settings
```bash
python3 scan_with_plugins.py /path/to/repo
```
- Scans: `.xml .config .conf .properties .yaml .yml`
- Detects: All password-like elements
- Output: Prints to stdout

---

#### 2. Scan and save to file
```bash
python3 scan_with_plugins.py /path/to/repo --output results.json
```
- Same as above, but saves to `results.json`

---

### Production Scanning

#### 3. Production secrets only
```bash
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod-secrets.json
```
- Includes: `prod_*`, `production_*`, `live_*`, generic `<password>` tags
- Excludes: `test_*`, `dev_*`, `example_*`, etc.
- Min length: 6 characters

---

#### 4. Custom production filter
```bash
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "database_prod" "api_live" \
  --exclude-entities "test_.*" \
  --min-length 8 \
  --output custom-prod.json
```
- Only scans specific production entities
- Excludes all test entities
- 8+ character passwords only

---

### Targeted Scanning

#### 5. Scan only database credentials
```bash
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "database_.*" "db_.*" "connection.*" \
  --output db-secrets.json
```
- Focuses on database-related elements

---

#### 6. Scan only API keys
```bash
python3 scan_with_plugins.py /path/to/repo \
  --include-entities ".*api.*" ".*key.*" \
  --min-length 10 \
  --output api-keys.json
```
- Focuses on API key elements
- 10+ character keys only

---

### File Type Scanning

#### 7. Scan only XML files
```bash
python3 scan_with_plugins.py /path/to/repo \
  --extensions .xml \
  --output xml-secrets.json
```

---

#### 8. Scan XML and YAML files
```bash
python3 scan_with_plugins.py /path/to/repo \
  --extensions .xml .yaml .yml \
  --output config-secrets.json
```

---

### Advanced Scanning

#### 9. Full context scan with multi-line support
```bash
python3 scan_xml_with_context.py /path/to/repo \
  --prod-only \
  --output detailed-results.json
```
- Parses XML structure
- Handles multi-line values
- Provides element paths and parent context

---

#### 10. Fast scan without normalization
```bash
python3 scan_xml_with_context.py /path/to/repo \
  --no-normalize \
  --output fast-results.json
```
- Skips normalization (faster)
- May miss multi-line secrets

---

#### 11. Scan without Unix crypt detection
```bash
python3 scan_with_plugins.py /path/to/repo \
  --disable-unix-crypt \
  --output plaintext-only.json
```
- Only detects plaintext passwords
- Ignores bcrypt/SHA-512/MD5 hashes

---

### Exclude Test Data

#### 12. Exclude all test/dev/example data
```bash
python3 scan_with_plugins.py /path/to/repo \
  --exclude-entities "test_.*" "dev_.*" "example_.*" "sample_.*" "demo_.*" \
  --output prod-only.json
```
- Equivalent to `--prod-only` but without include filters

---

### Real-World Workflows

#### 13. Daily production secret audit
```bash
#!/bin/bash
DATE=$(date +%Y%m%d)
OUTPUT_DIR=~/security-audits

python3 scan_with_plugins.py /path/to/production-repo \
  --prod-only \
  --min-length 8 \
  --output "$OUTPUT_DIR/prod-audit-$DATE.json"

# Review results
cat "$OUTPUT_DIR/prod-audit-$DATE.json" | jq '.secrets[] | {file, secret}'

# Clean up
shred -u "$OUTPUT_DIR/prod-audit-$DATE.json"
```

---

#### 14. Pre-commit hook to prevent secret commits
```bash
#!/bin/bash
# .git/hooks/pre-commit

# Scan staged files
python3 scan_with_plugins.py . \
  --prod-only \
  --output /tmp/pre-commit-scan.json

# Check if secrets found
SECRET_COUNT=$(jq '.total_secrets_found' /tmp/pre-commit-scan.json)

if [ "$SECRET_COUNT" -gt 0 ]; then
  echo "ERROR: Found $SECRET_COUNT production secret(s) in staged files!"
  jq '.secrets[] | {file, line_number, secret}' /tmp/pre-commit-scan.json
  rm /tmp/pre-commit-scan.json
  exit 1
fi

rm /tmp/pre-commit-scan.json
exit 0
```

---

#### 15. CI/CD integration
```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install dependencies
        run: pip install detect-secrets

      - name: Scan for secrets
        run: |
          python3 scan_with_plugins.py . \
            --prod-only \
            --output secrets-report.json

      - name: Check results
        run: |
          SECRET_COUNT=$(jq '.total_secrets_found' secrets-report.json)
          if [ "$SECRET_COUNT" -gt 0 ]; then
            echo "Found $SECRET_COUNT secret(s)!"
            jq '.secrets' secrets-report.json
            exit 1
          fi
```

---

## Tips and Best Practices

### 1. Start Broad, Then Narrow
```bash
# First, scan everything
python3 scan_with_plugins.py /repo --output all-secrets.json

# Review results, then narrow down
python3 scan_with_plugins.py /repo --prod-only --output prod-secrets.json
```

---

### 2. Use `--prod-only` for Production Repos
```bash
# For production repositories
python3 scan_with_plugins.py /prod-repo --prod-only
```

---

### 3. Increase `--min-length` to Reduce Noise
```bash
# Too many short passwords?
python3 scan_with_plugins.py /repo --min-length 8
```

---

### 4. Store Results Outside Repository
```bash
# NEVER commit results!
python3 scan_with_plugins.py /repo \
  --output ~/security/scan-results.json
```

---

### 5. Use `scan_xml_with_context.py` for Complex XML
```bash
# If you have multi-line XML
python3 scan_xml_with_context.py /repo --output results.json
```

---

### 6. Combine with `jq` for Analysis
```bash
# Find all secrets in production database configs
python3 scan_with_plugins.py /repo --output results.json

# Extract just the secret values
jq '.secrets[] | .secret' results.json

# Group by file
jq '.secrets | group_by(.file)' results.json

# Count by type
jq '.secrets | group_by(.type) | map({type: .[0].type, count: length})' results.json
```

---

## Common Issues

### Issue: Too many false positives

**Solution:** Increase `--min-length` or use `--prod-only`
```bash
python3 scan_with_plugins.py /repo --min-length 8 --prod-only
```

---

### Issue: Missing secrets in multi-line XML

**Solution:** Use `scan_xml_with_context.py` (without `--no-normalize`)
```bash
python3 scan_xml_with_context.py /repo --output results.json
```

---

### Issue: Too slow on large repos

**Solution:** Use `--no-normalize` or `--extensions` to limit scope
```bash
python3 scan_xml_with_context.py /repo \
  --no-normalize \
  --extensions .xml \
  --output results.json
```

---

### Issue: Finding test data I don't care about

**Solution:** Use `--exclude-entities`
```bash
python3 scan_with_plugins.py /repo \
  --exclude-entities "test_.*" "example_.*" \
  --output results.json
```

---

## Quick Reference

### Most Common Commands

```bash
# 1. Basic scan
python3 scan_with_plugins.py /repo --output results.json

# 2. Production scan
python3 scan_with_plugins.py /repo --prod-only --output prod.json

# 3. XML with multi-line support
python3 scan_xml_with_context.py /repo --output results.json

# 4. Fast XML scan
python3 scan_xml_with_context.py /repo --no-normalize --output results.json

# 5. Custom filtering
python3 scan_with_plugins.py /repo \
  --include-entities "prod_.*" \
  --exclude-entities "test_.*" \
  --min-length 8 \
  --output results.json
```

---

## Getting Help

```bash
# Get help for scan_with_plugins.py
python3 scan_with_plugins.py --help

# Get help for scan_xml_with_context.py
python3 scan_xml_with_context.py --help
```

---

## Security Reminder

⚠️ **Output files contain ACTUAL SECRET VALUES!**

- NEVER commit `*results.json`, `*secrets.json` files
- Store results outside repository
- Use `.gitignore` protection (already configured)
- Encrypt results if storing long-term
- Use `shred -u` to securely delete results after review

```bash
# Secure workflow
python3 scan_with_plugins.py /repo --output /tmp/scan.json
jq '.secrets' /tmp/scan.json  # Review
shred -u /tmp/scan.json       # Securely delete
```
