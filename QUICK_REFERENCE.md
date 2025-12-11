# Quick Reference - XML Secret Detection Plugins

## Installation
```bash
pip install -e .
```

## Quick Commands

### Test Plugins
```bash
python3 test_plugins.py
```

### Scan Repository
```bash
# Basic scan
python3 scan_with_plugins.py /path/to/repo --output results.json

# Production only
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod.json

# Custom filtering
python3 scan_with_plugins.py /path/to/repo \
  --include-entities "prod_.*" "database_.*" \
  --exclude-entities "test_.*" "dev_.*" \
  --output results.json
```

## Python API

### XMLPasswordPlugin
```python
from xml_plugins import XMLPasswordPlugin

# Production only
plugin = XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*'],
    exclude_entities=['test_.*', 'dev_.*']
)

# Scan file
with open('config.xml') as f:
    for line_num, line in enumerate(f, 1):
        for secret in plugin.analyze_line('config.xml', line, line_num):
            print(f"{line_num}: {secret.secret_value}")
```

### UnixCryptPlugin
```python
from xml_plugins import UnixCryptPlugin

# Only SHA-512 and bcrypt
plugin = UnixCryptPlugin(
    detect_des=False,
    detect_md5=False,
    detect_sha512=True,
    detect_bcrypt=True
)
```

## Configuration Options

### XMLPasswordPlugin
| Option | Type | Description |
|--------|------|-------------|
| `include_entities` | List[str] | Regex patterns to INCLUDE |
| `exclude_entities` | List[str] | Regex patterns to EXCLUDE |
| `include_attributes` | List[str] | Attribute patterns to INCLUDE |
| `exclude_attributes` | List[str] | Attribute patterns to EXCLUDE |
| `min_password_length` | int | Minimum length (default: 4) |

### UnixCryptPlugin
| Option | Type | Description |
|--------|------|-------------|
| `detect_des` | bool | Detect DES hashes |
| `detect_md5` | bool | Detect MD5 hashes |
| `detect_bcrypt` | bool | Detect bcrypt hashes |
| `detect_sha256` | bool | Detect SHA-256 hashes |
| `detect_sha512` | bool | Detect SHA-512 hashes |

## Common Patterns

### Production Secrets Only
```python
include_entities=['prod_.*', 'production_.*', 'live_.*']
exclude_entities=['test_.*', 'dev_.*', 'staging_.*']
```

### Database Credentials Only
```python
include_entities=['database_.*', 'db_.*', 'datasource_.*']
include_attributes=['password', 'passwd', 'connectionString']
```

### Exclude Test Data
```python
exclude_entities=['test_.*', 'example_.*', 'sample_.*', 'demo_.*']
```

## Output Fields
- `file` - File path
- `line_number` - Line number
- `type` - Secret type (XML Password or Unix Crypt Hash)
- `secret` - **Actual secret value**
- `line_content` - Full line content

## Files
- `xml_plugins.py` - Plugin implementations
- `scan_with_plugins.py` - CLI wrapper
- `test_plugins.py` - Tests and examples
- `README.md` - Full documentation
