# Usage Examples - XML Secret Detection

Complete examples showing how to use the detect-secrets plugins.

## Quick Start

### 1. Installation
```bash
pip install -e .
```

### 2. Validate Installation
```bash
# Run validation tests
./validate.sh

# Run plugin unit tests
python3 test_plugins.py
```

### 3. Try the Demo
```bash
# Run comprehensive demo
./demo.sh
```

## Basic Usage

### Scan a Directory

```bash
# Scan all XML files in a directory
python3 scan_with_plugins.py /path/to/repo --output results.json

# View results
cat results.json | python3 -m json.tool
```

### Scan with Production Filter

```bash
# Only detect production secrets
python3 scan_with_plugins.py /path/to/repo --prod-only --output prod-secrets.json
```

## Filtering Examples

### Example 1: Production Secrets Only

**Command:**
```bash
python3 scan_with_plugins.py samples --prod-only --output prod_results.json
```

**What it does:**
- Includes: `prod_.*`, `production_.*`, `live_.*`
- Excludes: `test_.*`, `dev_.*`, `example_.*`, `sample_.*`, `demo_.*`
- Minimum length: 6 characters

**Sample output:**
```
✓ Found 12 production secrets
  - prod_database_config.xml:8 - prod_password
  - prod_database_config.xml:15 - prod_api_key
  - mixed_config.xml:32 - production_api_key
```

### Example 2: Database Configurations Only

**Command:**
```bash
python3 scan_with_plugins.py samples \
  --include-entities "database_.*" "db_.*" \
  --exclude-entities "test.*" \
  --output database_secrets.json
```

**What it does:**
- Only scans entities with `database_` or `db_` prefix
- Excludes anything starting with `test`

**Sample output:**
```
✓ Found 6 database secrets
  - database_only.xml:7 - database_prod_primary password
  - database_only.xml:13 - database_prod_analytics password
```

### Example 3: API Keys and Secrets Only

**Command:**
```bash
python3 scan_with_plugins.py samples \
  --include-attributes "api_key" "secret_key" "apiKey" \
  --output api_keys.json
```

**What it does:**
- Only checks specific attribute names
- Ignores password fields

### Example 4: Exclude Test Data

**Command:**
```bash
python3 scan_with_plugins.py samples \
  --exclude-entities "test_.*" "dev_.*" "example_.*" "sample_.*" \
  --output no_test_data.json
```

**What it does:**
- Scans everything except test/dev/example data
- Blacklist approach

### Example 5: High Security (Strict Filtering)

**Command:**
```bash
python3 scan_with_plugins.py samples \
  --include-entities "prod_.*" "production_.*" \
  --min-length 8 \
  --output high_security.json
```

**What it does:**
- Only production entities
- Passwords must be 8+ characters
- Reduces false positives

## Python API Examples

### Example 1: Basic Scanning

```python
from xml_plugins import XMLPasswordPlugin

# Create plugin
plugin = XMLPasswordPlugin()

# Scan a file
with open('config.xml') as f:
    for line_num, line in enumerate(f, 1):
        for secret in plugin.analyze_line('config.xml', line, line_num):
            print(f"Line {line_num}: {secret.secret_value}")
```

### Example 2: Production Filter

```python
from xml_plugins import XMLPasswordPlugin

# Configure for production only
plugin = XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*', 'live_.*'],
    exclude_entities=['test_.*', 'dev_.*', 'example_.*'],
    min_password_length=6
)

# Scan
with open('prod_config.xml') as f:
    for line_num, line in enumerate(f, 1):
        for secret in plugin.analyze_line('prod_config.xml', line, line_num):
            print(f"Found production secret at line {line_num}")
```

### Example 3: Scan Directory Recursively

```python
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin
from pathlib import Path

# Create plugins
xml_plugin = XMLPasswordPlugin(include_entities=['prod_.*'])
unix_plugin = UnixCryptPlugin()

# Scan all XML files
secrets = []
for xml_file in Path('/path/to/repo').rglob('*.xml'):
    with open(xml_file) as f:
        for line_num, line in enumerate(f, 1):
            # Check for passwords
            secrets.extend(xml_plugin.analyze_line(str(xml_file), line, line_num))
            # Check for hashes
            secrets.extend(unix_plugin.analyze_line(str(xml_file), line, line_num))

print(f"Found {len(secrets)} secrets")
```

### Example 4: Database Credentials Only

```python
from xml_plugins import XMLPasswordPlugin

plugin = XMLPasswordPlugin(
    include_entities=['database_.*', 'db_.*', 'datasource_.*'],
    include_attributes=['password', 'passwd', 'connectionString']
)

# Scan specific file
with open('database_config.xml') as f:
    for line_num, line in enumerate(f, 1):
        for secret in plugin.analyze_line('database_config.xml', line, line_num):
            print(f"DB Secret: {secret.secret_value[:20]}...")
```

### Example 5: Unix Crypt Hashes Only

```python
from xml_plugins import UnixCryptPlugin

# Only detect SHA-512 and bcrypt
plugin = UnixCryptPlugin(
    detect_des=False,
    detect_md5=False,
    detect_bcrypt=True,
    detect_sha256=False,
    detect_sha512=True,
    detect_yescrypt=False
)

# Scan for hashes
with open('users.xml') as f:
    for line_num, line in enumerate(f, 1):
        for secret in plugin.analyze_line('users.xml', line, line_num):
            print(f"Line {line_num}: {secret.type} - {secret.secret_value[:30]}...")
```

### Example 6: Custom Secret Processor

```python
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin
import json

def scan_and_report(file_path, output_file):
    """Scan a file and generate a report."""
    xml_plugin = XMLPasswordPlugin(include_entities=['prod_.*'])
    unix_plugin = UnixCryptPlugin()

    results = []

    with open(file_path) as f:
        for line_num, line in enumerate(f, 1):
            for secret in xml_plugin.analyze_line(file_path, line, line_num):
                results.append({
                    'line': line_num,
                    'type': secret.type,
                    'secret': secret.secret_value,
                    'severity': 'HIGH' if 'prod' in line.lower() else 'MEDIUM'
                })

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    return results

# Use it
secrets = scan_and_report('config.xml', 'report.json')
print(f"Generated report with {len(secrets)} secrets")
```

## Sample Files

The `samples/` directory contains example XML files:

### Try These Commands

```bash
# 1. Scan all samples
python3 scan_with_plugins.py samples --output all.json
cat all.json | python3 -m json.tool

# 2. Production only
python3 scan_with_plugins.py samples --prod-only --output prod.json
cat prod.json | python3 -m json.tool

# 3. Database configs
python3 scan_with_plugins.py samples \
  --include-entities "database_.*" "db_.*" \
  --output db.json

# 4. Compare results
echo "All secrets: $(python3 -c 'import json; print(json.load(open(\"all.json\"))[\"total_secrets_found\"])')"
echo "Prod only: $(python3 -c 'import json; print(json.load(open(\"prod.json\"))[\"total_secrets_found\"])')"
```

## Common Workflows

### Workflow 1: Initial Repository Audit

```bash
# Step 1: Scan everything
python3 scan_with_plugins.py /path/to/repo --output initial_scan.json

# Step 2: Review results
cat initial_scan.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for secret in data['secrets']:
    print(f'{secret[\"file\"]}:{secret[\"line_number\"]} - {secret[\"type\"]}')
"

# Step 3: Identify false positives
# Add patterns to exclude

# Step 4: Rescan with filters
python3 scan_with_plugins.py /path/to/repo \
  --exclude-entities "test_.*" "example_.*" \
  --output filtered_scan.json
```

### Workflow 2: Production Security Audit

```bash
# Scan production configs only
python3 scan_with_plugins.py /path/to/repo/config \
  --prod-only \
  --min-length 8 \
  --output prod_audit.json

# Generate report
python3 -c "
import json
with open('prod_audit.json') as f:
    data = json.load(f)

print(f'Production Security Audit')
print(f'=' * 60)
print(f'Total secrets found: {data[\"total_secrets_found\"]}')
print()
print('Secrets by type:')
types = {}
for s in data['secrets']:
    types[s['type']] = types.get(s['type'], 0) + 1

for t, count in types.items():
    print(f'  {t}: {count}')
"
```

### Workflow 3: Continuous Monitoring

```bash
#!/bin/bash
# daily_scan.sh - Run daily secret scan

DATE=$(date +%Y%m%d)
OUTPUT="scans/scan_${DATE}.json"

python3 scan_with_plugins.py /path/to/repo \
  --prod-only \
  --output "$OUTPUT"

# Compare with previous day
PREV=$(ls scans/scan_*.json | tail -2 | head -1)
if [ -f "$PREV" ]; then
    echo "Comparing with $PREV"
    diff <(jq -S . "$PREV") <(jq -S . "$OUTPUT")
fi
```

## Output Processing

### Extract Specific Information

```bash
# List all files with secrets
cat results.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
files = set(s['file'] for s in data['secrets'])
for f in sorted(files):
    print(f)
"

# Count secrets by type
cat results.json | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
types = Counter(s['type'] for s in data['secrets'])
for t, count in types.items():
    print(f'{t}: {count}')
"

# Show only high-value secrets
cat results.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for s in data['secrets']:
    if any(keyword in s['line_content'].lower()
           for keyword in ['api_key', 'secret_key', 'private_key']):
        print(f'{s[\"file\"]}:{s[\"line_number\"]} - {s[\"type\"]}')
"
```

## Troubleshooting

### Too Many False Positives

**Problem:** Getting secrets that aren't real

**Solution:**
```bash
# Increase minimum length
python3 scan_with_plugins.py /repo --min-length 8

# Add exclusions
python3 scan_with_plugins.py /repo \
  --exclude-entities "test_.*" "example_.*" "sample_.*"

# Use production-only mode
python3 scan_with_plugins.py /repo --prod-only
```

### Missing Real Secrets

**Problem:** Not detecting known secrets

**Solution:**
```bash
# Lower minimum length
python3 scan_with_plugins.py /repo --min-length 3

# Check your filters
# Make sure include patterns match your naming

# Test on specific file
python3 -c "
from xml_plugins import XMLPasswordPlugin
plugin = XMLPasswordPlugin()
with open('your_file.xml') as f:
    for i, line in enumerate(f, 1):
        for secret in plugin.analyze_line('your_file.xml', line, i):
            print(f'Line {i}: {secret.secret_value}')
"
```

## Next Steps

- See **README.md** for full documentation
- See **README_PLUGINS.md** for all plugin options
- See **DETECT_SECRETS_GUIDE.md** for integration with detect-secrets CLI
- See **samples/README.md** for more about the sample files
