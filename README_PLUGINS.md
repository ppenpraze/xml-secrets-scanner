# XML Secret Detection - detect-secrets Plugins

Custom plugins for Yelp detect-secrets to detect XML passwords and Unix crypt hashes with flexible filtering.

## Quick Start

```bash
# Install
pip install -e .

# Test the plugins
python3 test_plugins.py

# Scan a repository
python3 scan_with_plugins.py /path/to/repo --output results.json
```

## What's Included

### 1. XMLPasswordPlugin
Detects passwords and secrets in XML files with configurable include/exclude patterns.

**Features:**
- Detects XML attributes: `password="secret"`, `api_key="..."`, etc.
- Detects XML elements: `<password>...</password>`, `<apiKey>...</apiKey>`, etc.
- Flexible entity filtering (include/exclude by regex)
- Flexible attribute filtering (include/exclude by regex)
- Automatic placeholder detection
- Configurable minimum password length

**Example:**
```python
from xml_plugins import XMLPasswordPlugin

# Only scan production entities
plugin = XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*'],
    exclude_entities=['test_.*', 'dev_.*'],
    min_password_length=6
)
```

### 2. UnixCryptPlugin
Detects Unix crypt format password hashes.

**Supported Formats:**
- Traditional DES (13 chars)
- MD5: `$1$salt$hash`
- bcrypt: `$2a$`, `$2b$`, `$2x$`, `$2y$`
- SHA-256: `$5$salt$hash`
- SHA-512: `$6$salt$hash`
- yescrypt: `$y$`, `$7$`

**Example:**
```python
from xml_plugins import UnixCryptPlugin

# Only detect bcrypt and SHA-512
plugin = UnixCryptPlugin(
    detect_des=False,
    detect_md5=False,
    detect_bcrypt=True,
    detect_sha256=False,
    detect_sha512=True
)
```

## Installation

```bash
# Clone or download this repository
cd /path/to/xml-secret-detection

# Install in development mode
pip install -e .

# Verify installation
python3 test_plugins.py
```

## Usage

### Option 1: Use the Scan Script (Recommended)

The easiest way to use the plugins is with the provided scan script:

```bash
# Basic scan
python3 scan_with_plugins.py /path/to/repo

# Scan production secrets only
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod-secrets.json

# Custom filters
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "prod_.*" "live_.*" \
  --exclude-entities "test_.*" "dev_.*" \
  --output results.json

# Specific file types
python3 scan_with_plugins.py /path/to/repo \
  --extensions .xml .yaml .properties \
  --output results.json
```

### Option 2: Use Python API Directly

```python
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin

# Create plugins
xml_plugin = XMLPasswordPlugin(
    include_entities=['prod_.*'],
    exclude_entities=['test_.*'],
    min_password_length=6
)

unix_plugin = UnixCryptPlugin()

# Scan a file
with open('config.xml', 'r') as f:
    for line_num, line in enumerate(f, 1):
        # Check for passwords
        for secret in xml_plugin.analyze_line('config.xml', line, line_num):
            print(f"Line {line_num}: Found {secret.type}: {secret.secret_value}")

        # Check for hashes
        for secret in unix_plugin.analyze_line('config.xml', line, line_num):
            print(f"Line {line_num}: Found {secret.type}: {secret.secret_value}")
```

### Option 3: Integration with detect-secrets (Advanced)

While the plugins are compatible with detect-secrets, the CLI intentionally hides secrets.
For auditing purposes where you need to see the actual secrets, use Options 1 or 2 above.

## Configuration Options

### XMLPasswordPlugin Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_entities` | List[str] | None | Regex patterns for entities to INCLUDE |
| `exclude_entities` | List[str] | None | Regex patterns for entities to EXCLUDE |
| `include_attributes` | List[str] | None | Regex patterns for attributes to INCLUDE |
| `exclude_attributes` | List[str] | None | Regex patterns for attributes to EXCLUDE |
| `min_password_length` | int | 4 | Minimum password length to detect |
| `detect_empty` | bool | False | Whether to detect empty passwords |

### UnixCryptPlugin Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `detect_des` | bool | True | Detect DES hashes |
| `detect_md5` | bool | True | Detect MD5 hashes |
| `detect_bcrypt` | bool | True | Detect bcrypt hashes |
| `detect_sha256` | bool | True | Detect SHA-256 hashes |
| `detect_sha512` | bool | True | Detect SHA-512 hashes |
| `detect_yescrypt` | bool | True | Detect yescrypt hashes |

## Filtering Logic

### Include/Exclude Behavior

1. **Exclude First**: If a pattern matches any exclude filter, it's excluded
2. **Include Second**: If include filters exist, pattern must match at least one
3. **Default Allow**: If no filters match, use default behavior

### Examples

**Production Only:**
```python
XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*'],
    exclude_entities=['test_.*', 'dev_.*']
)
# Matches: prod_password, production_secret
# Skips: test_password, dev_secret, anything else
```

**Blacklist Approach:**
```python
XMLPasswordPlugin(
    exclude_entities=['test_.*', 'example_.*', 'sample_.*']
)
# Matches: everything except test_*, example_*, sample_*
```

**Specific Attributes Only:**
```python
XMLPasswordPlugin(
    include_attributes=['password', 'api_key', 'secret']
)
# Only checks: password, api_key, secret attributes
# Skips: other attributes
```

## Output Format

The scan script outputs JSON with detected secrets:

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
      "secret": "$6$salt$hash...",
      "line_content": "<hash>$6$salt$hash...</hash>"
    }
  ]
}
```

## Files in This Repository

```
.
├── xml_plugins.py              # Plugin implementations
├── scan_with_plugins.py        # Scan script using plugins
├── test_plugins.py             # Unit tests for plugins
├── xml_secret_detector.py      # Standalone tool (alternative approach)
├── setup.py                    # Package installation
├── requirements.txt            # Dependencies
├── DETECT_SECRETS_GUIDE.md    # Comprehensive guide
├── README_PLUGINS.md          # This file
├── .secrets.production.yaml   # Production config example
└── .secrets.all.yaml          # High sensitivity config example
```

## Common Use Cases

### 1. Audit Existing Repository

```bash
# Find all secrets with actual values shown
python3 scan_with_plugins.py /path/to/repo --output audit-results.json

# Review the output
cat audit-results.json | jq '.secrets[] | {file, line_number, type, secret}'
```

### 2. Production Secrets Only

```bash
# Use the prod-only flag
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod-secrets.json
```

### 3. Custom Filtering

```bash
# Scan database configs only
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "database_.*" "db_.*" \
  --exclude-entities "test_.*" \
  --extensions .xml .properties
```

### 4. Find Only Unix Crypt Hashes

```bash
# Use Python API for more control
python3 -c "
from xml_plugins import UnixCryptPlugin
from pathlib import Path

plugin = UnixCryptPlugin()
for f in Path('/path/to/repo').rglob('*.xml'):
    with open(f) as file:
        for i, line in enumerate(file, 1):
            for secret in plugin.analyze_line(str(f), line, i):
                print(f'{f}:{i} - {secret.secret_value}')
"
```

## Comparison with Standalone Tool

| Feature | scan_with_plugins.py | xml_secret_detector.py |
|---------|---------------------|------------------------|
| Shows secrets | ✅ Yes | ✅ Yes |
| Uses detect-secrets | ✅ Yes | ❌ No |
| XML filtering | ✅ Yes | ✅ Yes |
| Unix crypt detection | ✅ Yes | ✅ Yes |
| Include/exclude entities | ✅ Yes | ❌ No |
| Pre-commit compatible | ✅ Yes | ❌ No |
| Dependencies | detect-secrets | None |

## Troubleshooting

### False Positives

**Problem:** Too many false positives

**Solutions:**
```bash
# Add common false positives to exclude
python3 scan_with_plugins.py /path/to/repo \
  --exclude-entities "test_.*" "example_.*" "sample_.*"

# Increase minimum password length
python3 scan_with_plugins.py /path/to/repo --min-length 8

# Disable DES detection (often causes false positives)
# Edit scan_with_plugins.py or use Python API with detect_des=False
```

### Missing Secrets

**Problem:** Not detecting known secrets

**Solutions:**
```bash
# Lower minimum length
python3 scan_with_plugins.py /path/to/repo --min-length 3

# Check if being filtered by exclude patterns
# Remove --exclude-entities flag temporarily

# Test plugin directly
python3 test_plugins.py
```

### Want to Use with Pre-commit

**Problem:** Need pre-commit integration

**Solution:** Use detect-secrets baseline approach (see DETECT_SECRETS_GUIDE.md)

## Testing

Run the test suite:

```bash
# Run plugin tests
python3 test_plugins.py

# Test on example file
python3 scan_with_plugins.py . --extensions .xml
```

Expected output:
- ✅ XMLPasswordPlugin detects passwords in attributes and elements
- ✅ Placeholder values are filtered out
- ✅ Include/exclude patterns work correctly
- ✅ UnixCryptPlugin detects various hash formats

## Best Practices

1. **Start Broad, Then Filter**
   - First scan without filters
   - Identify false positives
   - Add to exclude patterns

2. **Use Production-Only Mode for Audits**
   ```bash
   python3 scan_with_plugins.py /repo --prod-only
   ```

3. **Save Results for Comparison**
   ```bash
   python3 scan_with_plugins.py /repo --output baseline.json
   # Later, compare new scan with baseline
   ```

4. **Combine with Other Tools**
   - Use these plugins for XML-specific detection
   - Use detect-secrets built-in plugins for other secret types
   - Use the standalone tool when you need custom output format

5. **Review All Detections**
   - Not all detections are real secrets
   - Always manually review before taking action
   - Use the line_content field for context

## Contributing

To add new detection patterns:

1. Edit `xml_plugins.py`
2. Add patterns to `XMLPasswordPlugin` or `UnixCryptPlugin`
3. Add tests to `test_plugins.py`
4. Run tests: `python3 test_plugins.py`

## License

This tool is provided as-is for security auditing purposes.

## Support

For questions or issues:
1. Check `DETECT_SECRETS_GUIDE.md` for comprehensive documentation
2. Review `test_plugins.py` for usage examples
3. Test with `python3 test_plugins.py` to verify setup
