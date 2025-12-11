# XML Secret Detection - Project Summary

Custom detect-secrets plugins for detecting secrets in XML repositories with flexible entity and attribute filtering.

## Overview

This project provides custom plugins for Yelp detect-secrets that address the limitations of vanilla detect-secrets when scanning XML repositories:

**Problems with vanilla detect-secrets:**
- ❌ No XML-aware detection
- ❌ Cannot detect Unix crypt format passwords
- ❌ High sensitivity causes excessive false positives
- ❌ Limited filtering options for XML-specific patterns

**Our solution:**
- ✅ XML-aware password detection in attributes and elements
- ✅ Unix crypt hash detection (MD5, SHA-256, SHA-512, bcrypt)
- ✅ Flexible entity-level filtering (include/exclude XML nodes by regex)
- ✅ Flexible attribute-level filtering (include/exclude attributes by regex)
- ✅ Automatic placeholder detection
- ✅ Shows actual detected secrets for verification

## Plugins Provided

### 1. XMLPasswordPlugin

Detects passwords and secrets in XML files with configurable filtering.

**Key Features:**
- Detects passwords in XML attributes: `password="secret"`, `api_key="..."`
- Detects passwords in XML elements: `<password>secret</password>`
- Include/exclude specific XML entities (nodes) by regex pattern
- Include/exclude specific attributes by regex pattern
- Automatic placeholder filtering (password, changeme, example, etc.)
- Configurable minimum password length

**Configuration Example:**
```python
XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*'],  # Only production
    exclude_entities=['test_.*', 'dev_.*'],         # Exclude test/dev
    include_attributes=['password', 'api_key'],     # Specific attributes
    min_password_length=6                           # Minimum 6 chars
)
```

### 2. UnixCryptPlugin

Detects Unix crypt format password hashes.

**Supported Formats:**
- Traditional DES (13 characters)
- MD5: `$1$salt$hash`
- bcrypt: `$2a$`, `$2b$`, `$2x$`, `$2y$`
- SHA-256: `$5$salt$hash`
- SHA-512: `$6$salt$hash`
- yescrypt: `$y$`, `$7$`

**Configuration Example:**
```python
UnixCryptPlugin(
    detect_des=False,      # Disable DES (reduces false positives)
    detect_bcrypt=True,    # Enable bcrypt
    detect_sha512=True     # Enable SHA-512
)
```

## Quick Start

### Installation

```bash
# Install the plugins
pip install -e .

# Verify installation
python3 test_plugins.py
```

### Basic Usage

```bash
# Scan a repository
python3 scan_with_plugins.py /path/to/repo --output results.json

# Scan production secrets only
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod.json

# Custom entity filtering
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "database_.*" "api_.*" \
  --exclude-entities "test_.*" \
  --output results.json
```

## Project Structure

```
xml-secret-detection/
├── xml_plugins.py              # Core plugin implementations (350+ lines)
├── scan_with_plugins.py        # CLI wrapper for easy scanning (230+ lines)
├── test_plugins.py             # Unit tests and examples
├── setup.py                    # Package installation
├── requirements.txt            # Dependencies (detect-secrets)
├── .secrets.production.yaml   # Production-only config example
├── .secrets.all.yaml          # High sensitivity config example
├── .secrets.baseline           # Default baseline config
├── test_examples.xml           # Test data with various secret types
├── README.md                  # Main documentation (Quick Start)
├── README_PLUGINS.md          # Detailed plugin documentation
├── DETECT_SECRETS_GUIDE.md    # detect-secrets integration guide
└── PROJECT_SUMMARY.md         # This file
```

## Usage Examples

### Example 1: Audit a Repository

```bash
# Scan everything
python3 scan_with_plugins.py /path/to/repo --output all-secrets.json

# Review results
cat all-secrets.json | jq '.secrets[] | {file, line_number, type}'
```

### Example 2: Production Secrets Only

```bash
# Use --prod-only flag
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod.json
```

### Example 3: Custom Entity Filtering

```bash
# Only database and API configurations
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "database_.*" "db_.*" "api_.*" \
  --exclude-entities "test_.*" "example_.*" \
  --output results.json
```

### Example 4: Python API

```python
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin

# Configure plugins
xml_plugin = XMLPasswordPlugin(
    include_entities=['prod_.*'],
    exclude_entities=['test_.*'],
    min_password_length=6
)

unix_plugin = UnixCryptPlugin()

# Scan a file
with open('config.xml') as f:
    for line_num, line in enumerate(f, 1):
        # Check for passwords
        for secret in xml_plugin.analyze_line('config.xml', line, line_num):
            print(f"Line {line_num}: {secret.type} = {secret.secret_value}")

        # Check for hashes
        for secret in unix_plugin.analyze_line('config.xml', line, line_num):
            print(f"Line {line_num}: {secret.type} = {secret.secret_value}")
```

## Configuration Strategies

### Strategy 1: Whitelist (Include Only Specific Patterns)

Best for: Production audits, focusing on specific types of secrets

```python
XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*', 'live_.*'],
    include_attributes=['password', 'api_key', 'secret']
)
```

### Strategy 2: Blacklist (Exclude Known False Positives)

Best for: Initial audits, broad scanning

```python
XMLPasswordPlugin(
    exclude_entities=['test_.*', 'dev_.*', 'example_.*', 'sample_.*'],
    min_password_length=8
)
```

### Strategy 3: Combined (Whitelist + Blacklist)

Best for: Precise control, production environments

```python
XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*'],  # Only production
    exclude_entities=['prod_test_.*'],              # Except test data
    min_password_length=6
)
```

## Output Format

All tools output JSON with the following structure:

```json
{
  "scan_directory": "/path/to/repo",
  "total_secrets_found": 3,
  "secrets": [
    {
      "file": "config/database.xml",
      "line_number": 42,
      "type": "XML Password",
      "secret": "SuperSecret123!",
      "line_content": "<password>SuperSecret123!</password>"
    },
    {
      "file": "config/users.xml",
      "line_number": 15,
      "type": "Unix Crypt Hash",
      "secret": "$6$rounds=5000$salt$hash...",
      "line_content": "<hash>$6$rounds=5000$salt$hash...</hash>"
    }
  ]
}
```

**Key fields:**
- `file`: Path to file containing the secret
- `line_number`: Line number in the file
- `type`: Type of secret detected (XML Password or Unix Crypt Hash)
- `secret`: **The actual secret value** (for verification)
- `line_content`: Full line content for context

## Filtering Logic Details

### Entity Filtering

**Include Entities:**
- If specified, ONLY entities matching these patterns are checked
- Uses regex matching
- Example: `include_entities=['prod_.*']` only checks `prod_password`, `prod_secret`, etc.

**Exclude Entities:**
- If specified, entities matching these patterns are SKIPPED
- Applied before include patterns
- Example: `exclude_entities=['test_.*']` skips `test_password`, `test_secret`, etc.

**Execution Order:**
1. Check exclude patterns → if matched, skip
2. Check include patterns → if specified and not matched, skip
3. Otherwise, proceed with detection

### Attribute Filtering

Same logic as entity filtering but applies to XML attributes:
- `include_attributes`: Only check these attribute names
- `exclude_attributes`: Skip these attribute names

## Testing

All plugins have been tested with the included test suite:

```bash
python3 test_plugins.py
```

**Test Coverage:**
- ✅ XMLPasswordPlugin detects passwords in attributes
- ✅ XMLPasswordPlugin detects passwords in elements
- ✅ Placeholder values are properly filtered
- ✅ Include entity patterns work correctly
- ✅ Exclude entity patterns work correctly
- ✅ UnixCryptPlugin detects SHA-512 hashes
- ✅ UnixCryptPlugin detects bcrypt hashes
- ✅ Combined filtering (include + exclude) works

## Common Workflows

### Workflow 1: Initial Repository Audit

```bash
# Step 1: Scan everything
python3 scan_with_plugins.py /repo --output initial-scan.json

# Step 2: Review and identify false positives
cat initial-scan.json | jq '.secrets[].secret'

# Step 3: Create filtered scan
python3 scan_with_plugins.py /repo \
  --exclude-entities "test_.*" "example_.*" \
  --output filtered-scan.json
```

### Workflow 2: Production Security Audit

```bash
# Scan only production entities
python3 scan_with_plugins.py /repo \
  --include-entities "prod_.*" "production_.*" \
  --exclude-entities "prod_test_.*" \
  --min-length 8 \
  --output prod-audit.json

# Review critical findings
cat prod-audit.json | jq '.secrets[] | select(.type == "XML Password")'
```

### Workflow 3: Continuous Monitoring

```bash
# Daily scan
python3 scan_with_plugins.py /repo --output "scan-$(date +%Y%m%d).json"

# Compare with previous day
diff <(jq -S . scan-20241210.json) <(jq -S . scan-20241211.json)
```

## Advantages Over Vanilla detect-secrets

| Feature | Our Plugins | Vanilla detect-secrets |
|---------|-------------|------------------------|
| XML-aware detection | ✅ Yes | ❌ No |
| Unix crypt detection | ✅ Yes | ❌ No |
| Entity-level filtering | ✅ Yes (regex) | ❌ No |
| Attribute-level filtering | ✅ Yes (regex) | ❌ No |
| Shows actual secrets | ✅ Yes | ❌ No (by design) |
| Placeholder detection | ✅ Automatic | ⚠️ Limited |
| Configurable sensitivity | ✅ Per-plugin | ⚠️ Global only |

## Security Considerations

1. **Output Contains Secrets**
   - JSON output includes actual secret values
   - Store output files securely
   - Don't commit output to version control
   - Add to `.gitignore`: `*-secrets.json`, `*-results.json`

2. **Use Appropriate Filters**
   - Production scans should use strict include patterns
   - Use `--prod-only` for production audits
   - Exclude test/development data

3. **Manual Review Required**
   - Not all detections are real secrets
   - Review line_content for context
   - Validate before taking action

## Documentation

- **README.md** - Quick start and common usage
- **README_PLUGINS.md** - Detailed plugin documentation with all configuration options
- **DETECT_SECRETS_GUIDE.md** - Integration with detect-secrets CLI and workflows
- **PROJECT_SUMMARY.md** - This file (complete project overview)

## Requirements

- Python 3.6+
- detect-secrets >= 1.4.0

Install with:
```bash
pip install -e .
```

## Support

For issues or questions:

1. **Test the plugins:** `python3 test_plugins.py`
2. **Check documentation:** See README_PLUGINS.md for all options
3. **Review examples:** See test_plugins.py for working code examples
4. **Check test data:** See test_examples.xml for sample secrets

## Summary

This project provides production-ready detect-secrets plugins that solve the limitations of vanilla detect-secrets when working with XML repositories:

✅ **XML-aware detection** - Understands XML structure
✅ **Flexible filtering** - Include/exclude entities and attributes by regex
✅ **Unix crypt support** - Detects password hashes
✅ **Reduced false positives** - Smart placeholder detection
✅ **Shows actual secrets** - For verification and auditing
✅ **Easy to use** - Simple CLI wrapper and Python API

The plugins are fully compatible with detect-secrets and can be integrated into existing workflows while providing the XML-specific capabilities and filtering that vanilla detect-secrets lacks.
