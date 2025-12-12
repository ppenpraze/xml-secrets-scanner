# xml-secrets-scanner

**Comprehensive secret detection tool** combining custom XML plugins with all detect-secrets built-in plugins for thorough repository scanning.

## What This Tool Detects

### 19 Plugin Types (Custom + Built-in)

**Custom XML Plugins:**
- ✅ XML-aware password detection in attributes and elements
- ✅ Unix crypt hash detection (MD5, SHA-256, SHA-512, bcrypt)
- ✅ Flexible include/exclude filtering by entity name (XML nodes)
- ✅ Flexible include/exclude filtering by attribute name

**Detect-Secrets Built-in Plugins:**
- ✅ AWS Access Keys
- ✅ Azure Storage Keys
- ✅ Basic Auth credentials (user:pass@host)
- ✅ Cloudant credentials
- ✅ Discord bot tokens
- ✅ GitLab tokens
- ✅ IBM Cloud IAM keys
- ✅ IBM COS HMAC credentials
- ✅ Keyword-based secrets (password=, api_key=, etc.)
- ✅ Mailchimp API keys
- ✅ NPM tokens
- ✅ OpenAI API keys
- ✅ Private keys (RSA/SSH)
- ✅ PyPI tokens
- ✅ SendGrid API keys
- ✅ Stripe API keys
- ✅ Telegram bot tokens

**Additional Features:**
- ✅ Automatic placeholder detection
- ✅ Ignores boolean/null values (true, false, null, enabled, etc.)
- ✅ Custom ignore values via `--ignore-values`
- ✅ High-entropy password detection
- ✅ Multi-line XML support
- ✅ Shows actual detected secrets for verification
- ✅ Flexible plugin enable/disable control

## Quick Start

```bash
# Install
pip install -e .

# Test
python3 test_plugins.py

# List all available plugins
python3 scan_with_plugins.py --list-plugins

# Scan with ALL plugins (19 types of secrets)
python3 scan_xml_with_context.py /path/to/repo --output results.json

# Scan production secrets only (with all plugins)
python3 scan_xml_with_context.py /path/to/repo --prod-only --output prod-secrets.json

# Scan with only specific plugins
python3 scan_with_plugins.py /path/to/repo --only xml_password,aws,private_key --output results.json

# Disable noisy plugins
python3 scan_with_plugins.py /path/to/repo --disable keyword,stripe --output results.json

# Ignore specific false positive values
python3 scan_with_plugins.py /path/to/repo --ignore-values "myapp" "localhost" --output results.json

# Fast directory scan (line-based)
python3 scan_with_plugins.py /path/to/repo --output results.json
```

**Note:** Use `scan_xml_with_context.py` for comprehensive scanning that handles multi-line XML and includes parent element context. It attempts to parse as XML first for any file and falls back to safe line-by-line scanning if parsing fails. Both scanners now use all 19 plugins by default. See [MULTILINE_XML_GUIDE.md](MULTILINE_XML_GUIDE.md) and [PLUGIN_INTEGRATION_SUMMARY.md](PLUGIN_INTEGRATION_SUMMARY.md) for details.

## Features

### XMLPasswordPlugin

Detects passwords and secrets in XML files with configurable filtering. Also supports common non-XML key/value formats (e.g., `key=value`, `key: value`) for plaintext and encryption material.

**What it detects:**
- XML attributes: `password="secret"`, `api_key="..."`, `auth_token="..."`
- XML elements: `<password>secret</password>`, `<apiKey>...</apiKey>`
- Plaintext secrets in non-XML files via `key=value` or `key: value`
- API keys, secrets, connection strings, private keys
- AES/encryption keys (heuristics for 128/192/256-bit hex or base64), e.g., `aes_key`, `encryption_key`, `cipher_key`

**Filtering options:**
- `include_entities`: Regex patterns for XML entities to INCLUDE (e.g., `prod_.*`)
- `exclude_entities`: Regex patterns for XML entities to EXCLUDE (e.g., `test_.*`)
- `include_attributes`: Regex patterns for attributes to INCLUDE
- `exclude_attributes`: Regex patterns for attributes to EXCLUDE
- `min_password_length`: Minimum password length (default: 4)

**Example:**
```python
from xml_plugins import XMLPasswordPlugin

# Only scan production entities
plugin = XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*', 'live_.*'],
    exclude_entities=['test_.*', 'dev_.*', 'example_.*'],
    min_password_length=6
)

# Scan a file
with open('config.xml') as f:
    for line_num, line in enumerate(f, 1):
        for secret in plugin.analyze_line('config.xml', line, line_num):
            print(f"Line {line_num}: {secret.secret_value}")
```

Non-XML key/value example (properties/conf):
```python
plugin = XMLPasswordPlugin()
line = 'encryption_key = zXJx3L8m7Y1+8eUqJ2y8Ww=='
for s in plugin.analyze_line('app.properties', line, 1):
    print(s.secret_value)
```

### UnixCryptPlugin

Detects Unix crypt format password hashes.

**Supported formats:**
- Traditional DES (13 characters) [disabled by default to reduce false positives; enable with `detect_des=True`]
- MD5: `$1$salt$hash`
- bcrypt: `$2a$`, `$2b$`, `$2x$`, `$2y$`
- SHA-256: `$5$salt$hash`
- SHA-512: `$6$salt$hash`
- yescrypt: `$y$`, `$7$`

**Configuration:**
```python
from xml_plugins import UnixCryptPlugin

# Only detect SHA-512 and bcrypt
plugin = UnixCryptPlugin(
    detect_des=False,
    detect_md5=False,
    detect_bcrypt=True,
    detect_sha256=False,
    detect_sha512=True
)

# If you need legacy DES as well (may increase false positives):
plugin_des = UnixCryptPlugin(detect_des=True)
```

## Installation

```bash
# Clone or download this repository
cd /path/to/xml-secret-detection

# Install dependencies and plugins
pip install -e .

# Verify installation
python3 test_plugins.py
```

## Plugin Management

### List Available Plugins

```bash
python3 scan_with_plugins.py --list-plugins
```

Output:
```
Available Plugins:
================================================================================
  [✓] xml_password         - Detect passwords in XML elements and attributes
  [✓] unix_crypt           - Detect Unix crypt password hashes
  [✓] aws                  - Detect AWS Access Keys
  [✓] azure_storage        - Detect Azure Storage Keys
  ... (19 total plugins)
```

### Enable Only Specific Plugins

```bash
# Scan for only AWS keys and private keys
python3 scan_with_plugins.py /path/to/repo --only aws,private_key

# Scan for only XML passwords (original behavior)
python3 scan_with_plugins.py /path/to/repo --only xml_password,unix_crypt
```

### Disable Specific Plugins

```bash
# Disable keyword plugin (can be noisy)
python3 scan_with_plugins.py /path/to/repo --disable keyword

# Disable multiple plugins
python3 scan_with_plugins.py /path/to/repo --disable stripe,discord,telegram,keyword
```

### Plugin Control with Context Scanner

Both scanners support the same plugin control options:

```bash
# scan_xml_with_context.py also supports --only and --disable
python3 scan_xml_with_context.py /path/to/repo --only xml_password,aws,openai --output results.json
```

## Usage

### Method 1: Use the Scan Script (Easiest)

```bash
# Basic scan
python3 scan_with_plugins.py /path/to/repo --output results.json

# Production secrets only
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod.json

# Custom entity filtering
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "database_.*" "api_.*" \
  --exclude-entities "test_.*" "dev_.*" \
  --output results.json

# Specific file extensions
python3 scan_with_plugins.py /path/to/repo \
  --extensions .xml .yaml .properties \
  --output results.json

# See all options
python3 scan_with_plugins.py --help
```

### Method 2: Use Python API Directly

```python
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin
from pathlib import Path

# Configure plugins
xml_plugin = XMLPasswordPlugin(
    include_entities=['prod_.*'],
    exclude_entities=['test_.*']
)
unix_plugin = UnixCryptPlugin()

# Scan files
for file_path in Path('/path/to/repo').rglob('*.xml'):
    with open(file_path) as f:
        for line_num, line in enumerate(f, 1):
            # Check for XML passwords
            for secret in xml_plugin.analyze_line(str(file_path), line, line_num):
                print(f"{file_path}:{line_num} - {secret.type}: {secret.secret_value}")

            # Check for Unix crypt hashes
            for secret in unix_plugin.analyze_line(str(file_path), line, line_num):
                print(f"{file_path}:{line_num} - {secret.type}: {secret.secret_value}")
```

## Configuration Examples

### Example 1: Production Secrets Only

```python
XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*', 'live_.*'],
    exclude_entities=['test_.*', 'dev_.*', 'staging_.*', 'example_.*']
)
```

### Example 2: Database Credentials Only

```python
XMLPasswordPlugin(
    include_entities=['database_.*', 'db_.*', 'datasource_.*'],
    include_attributes=['password', 'passwd', 'connectionString']
)
```

### Example 3: Exclude Test Data

```python
XMLPasswordPlugin(
    exclude_entities=['test_.*', 'example_.*', 'sample_.*', 'demo_.*'],
    min_password_length=8
)
```

## Output Format

The scan script produces JSON with detected secrets and plugin information:

```json
{
  "scan_directory": "/path/to/repo",
  "enabled_plugins": [
    "xml_password",
    "unix_crypt",
    "aws",
    "private_key",
    "keyword",
    "..."
  ],
  "total_secrets_found": 4,
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
    },
    {
      "file": "config/aws.properties",
      "line_number": 8,
      "type": "AWS Access Key",
      "secret": "AKIAIOSFODNN7EXAMPLE",
      "line_content": "aws_access_key=AKIAIOSFODNN7EXAMPLE"
    },
    {
      "file": "deploy/id_rsa",
      "line_number": 1,
      "type": "Private Key",
      "secret": "-----BEGIN RSA PRIVATE KEY-----",
      "line_content": "-----BEGIN RSA PRIVATE KEY-----"
    }
  ]
}
```

The summary shows which plugins were used:
```
Summary: Found 4 secrets using 19 plugins
```

## Common Use Cases

### 1. Audit Existing Repository

```bash
# Find all secrets
python3 scan_with_plugins.py /path/to/repo --output audit.json

# Review the results
cat audit.json | jq '.secrets[] | {file, line_number, type, secret}'
```

### 2. Scan Only Production Configs

```bash
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod-secrets.json
```

### 3. Custom Entity Filtering

```bash
# Only scan database and API configs
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "database_.*" "db_.*" "api_.*" \
  --exclude-entities "test_.*" \
  --output results.json
```

### 4. Continuous Monitoring

```bash
# Daily scan with dated output
python3 scan_with_plugins.py /path/to/repo \
  --output "scan-$(date +%Y%m%d).json"
```

## Configuration Files

Example YAML configurations for different scenarios:

**`.secrets.production.yaml`** - Production secrets only:
```yaml
plugins_used:
  - name: XMLPasswordPlugin
    path: file://xml_plugins.py::XMLPasswordPlugin
    include_entities: ["prod_.*", "production_.*", "live_.*"]
    exclude_entities: ["test_.*", "dev_.*", "example_.*"]
    min_password_length: 6
```

**`.secrets.all.yaml`** - High sensitivity:
```yaml
plugins_used:
  - name: XMLPasswordPlugin
    path: file://xml_plugins.py::XMLPasswordPlugin
    min_password_length: 3
  - name: UnixCryptPlugin
    path: file://xml_plugins.py::UnixCryptPlugin
```

## Filtering Logic

### How Include/Exclude Works

1. **Exclude First**: If entity/attribute matches any exclude pattern → excluded
2. **Include Second**: If include patterns exist, entity/attribute must match at least one
3. **Default**: If no patterns match, use default behavior

### Examples

**Whitelist approach** (only specific patterns):
```python
XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*']
)
# Only scans: prod_password, production_secret, etc.
# Skips: everything else
```

**Blacklist approach** (exclude specific patterns):
```python
XMLPasswordPlugin(
    exclude_entities=['test_.*', 'example_.*']
)
# Scans: everything except test_* and example_*
```

**Combined approach**:
```python
XMLPasswordPlugin(
    include_entities=['prod_.*'],      # Only production
    exclude_entities=['prod_test_.*']  # Except production tests
)
```

## Troubleshooting

### Too Many False Positives

**Solutions:**
```bash
# Increase minimum password length
python3 scan_with_plugins.py /repo --min-length 8

# Add common false positives to exclude
python3 scan_with_plugins.py /repo \
  --exclude-entities "test_.*" "example_.*" "sample_.*"

# Use production-only mode
python3 scan_with_plugins.py /repo --prod-only
```

### Missing Real Secrets

**Solutions:**
```bash
# Lower minimum length
python3 scan_with_plugins.py /repo --min-length 3

# Check if being filtered
# Remove exclude patterns temporarily

# Test plugins directly
python3 test_plugins.py
```

## Files in This Repository

```
.
├── xml_plugins.py              # Plugin implementations
├── scan_with_plugins.py        # Easy-to-use scan script
├── test_plugins.py             # Unit tests and examples
├── setup.py                    # Package installation
├── requirements.txt            # Dependencies
├── .secrets.production.yaml   # Production config example
├── .secrets.all.yaml          # High sensitivity config
├── README.md                  # This file
├── README_PLUGINS.md          # Detailed plugin documentation
├── DETECT_SECRETS_GUIDE.md    # detect-secrets integration guide
└── PROJECT_SUMMARY.md         # Project overview
```

## Testing

Run the test suite to verify everything works:

```bash
python3 test_plugins.py
```

Expected output:
- ✅ XMLPasswordPlugin detects passwords in attributes and elements
- ✅ Placeholder values (password, changeme, example) are filtered
- ✅ Include/exclude entity patterns work correctly
- ✅ UnixCryptPlugin detects SHA-512 and bcrypt hashes

## Documentation

- **This README** - Quick start and common usage
- **IGNORE_VALUES_GUIDE.md** - How to ignore false positives (true, false, custom values)
- **PLUGIN_INTEGRATION_SUMMARY.md** - Comprehensive plugin integration guide
- **README_PLUGINS.md** - Detailed plugin documentation with all options
- **DETECT_SECRETS_GUIDE.md** - Integration with detect-secrets CLI
- **MULTILINE_XML_GUIDE.md** - Multi-line XML support guide
- **DUAL_SCAN_DOCUMENTATION.md** - Dual scan approach details
- **PROJECT_SUMMARY.md** - Complete project overview

## Requirements

- Python 3.6+
- detect-secrets >= 1.4.0

Install with:
```bash
pip install -e .
```

## Scanning non-XML files and custom extensions

Single files are always attempted as XML first and fall back to line-by-line scanning on parse errors, regardless of extension. In directory scans, you can adjust extensions:

```bash
# Use default extended set (xml, config, conf, properties, yaml/yml, ini, cfg)
python3 scan_xml_with_context.py /path/to/repo --output results.json

# Add more extensions explicitly
python3 scan_xml_with_context.py /path/to/repo \
  --extensions .xml .config .conf .properties .yaml .yml .ini .cfg .txt \
  --output results.json

# Scan a single arbitrary file (XML-first, then fallback)
python3 scan_xml_with_context.py /etc/app.conf --output app-conf.json
```

## License

This tool is provided as-is for security testing and auditing purposes.

## Support

For issues or questions:
1. Run `python3 test_plugins.py` to verify setup
2. Check `README_PLUGINS.md` for detailed documentation
3. Review `DETECT_SECRETS_GUIDE.md` for detect-secrets integration
4. See `test_examples.xml` for example test data
