# Multi-Line XML Support Guide

This guide explains how to scan XML files with values spread across multiple lines, and how parent element context is included in the output.

## Problem with Line-Based Scanning

The basic `scan_with_plugins.py` scans files **line by line** and can miss secrets when XML elements span multiple lines:

### ❌ Missed by Line-Based Scanner:
```xml
<password>
    MySecretPassword123
</password>
```

### ✅ Detected by Line-Based Scanner:
```xml
<password>MySecretPassword123</password>
```

## Solution: XML Context Scanner

Use **`scan_xml_with_context.py`** which:

1. **Normalizes XML** - Reformats multi-line XML to single lines
2. **Parses XML structure** - Understands the XML tree
3. **Includes parent context** - Adds element path in output

## Usage

### Scan Single File
```bash
python3 scan_xml_with_context.py config.xml --output results.json
```

### Scan Directory
```bash
python3 scan_xml_with_context.py /path/to/repo --output results.json
```

### Production Secrets Only
```bash
python3 scan_xml_with_context.py /path/to/repo --prod-only --output prod.json
```

### Skip Normalization (Faster)
```bash
# Use when you know XML is already single-line formatted
python3 scan_xml_with_context.py /path/to/repo --no-normalize --output results.json
```

## Output Format with Context

The enhanced scanner includes **parent element information**:

```json
{
  "file": "config.xml",
  "element_path": "/configuration/database/prod_password",
  "parent_element": "prod_password",
  "type": "XML Password",
  "secret": "MySecretPassword123",
  "line_content": "<prod_password>MySecretPassword123</prod_password>",
  "detection_method": "element_value"
}
```

### Output Fields

| Field | Description | Example |
|-------|-------------|---------|
| `file` | File path | `config.xml` |
| `element_path` | Full XPath to element | `/configuration/database/password` |
| `parent_element` | Immediate parent element | `password` |
| `type` | Secret type | `XML Password` |
| `secret` | Actual secret value | `MySecret123` |
| `line_content` | Reconstructed XML line | `<password>MySecret123</password>` |
| `detection_method` | How it was found | `element_value` or `attribute` |
| `attribute_name` | Attribute name (if applicable) | `password` |

## Handling Multi-Line XML

### Example 1: Multi-Line Element Values

**Input XML:**
```xml
<configuration>
    <database>
        <prod_password>
            SecretPassword2024
        </prod_password>
    </database>
</configuration>
```

**With Normalization:**
```bash
python3 scan_xml_with_context.py config.xml --output results.json
```

**Output:**
```json
{
  "element_path": "/configuration/database/prod_password",
  "parent_element": "prod_password",
  "secret": "SecretPassword2024",
  "detection_method": "element_value"
}
```

### Example 2: Connection Strings

**Input XML:**
```xml
<prod_config>
    <connection_string>
        Server=prod-db.company.com;
        Password=MultiLineDBPassword2024;
    </connection_string>
</prod_config>
```

**Output:**
```json
{
  "element_path": "/prod_config/connection_string",
  "parent_element": "connection_string",
  "secret": "Server=prod-db.company.com;Password=MultiLineDBPassword2024;",
  "detection_method": "element_value"
}
```

### Example 3: Attributes (Always Single Line)

**Input XML:**
```xml
<server
    name="prod-server"
    password="ServerPassword123"
    ip="192.168.1.100"/>
```

**Output:**
```json
{
  "element_path": "/configuration/server",
  "parent_element": "server",
  "attribute_name": "password",
  "secret": "ServerPassword123",
  "detection_method": "attribute"
}
```

## XML Normalization

The `normalize_xml.py` script can be used standalone:

### Normalize Single File
```bash
python3 normalize_xml.py config.xml -o normalized.xml
```

### Normalize Directory
```bash
python3 normalize_xml.py /path/to/configs -d -o /path/to/normalized
```

### Normalize Recursively
```bash
python3 normalize_xml.py /path/to/repo -d -r -o /path/to/normalized
```

## Performance Considerations

### With Normalization (Default)
- **Pros:** Handles all XML formats, catches multi-line secrets
- **Cons:** Slower due to XML parsing
- **Use when:** XML files may have multi-line elements

### Without Normalization (--no-normalize)
- **Pros:** Faster, scans line-by-line
- **Cons:** May miss multi-line element values
- **Use when:** XML is already single-line formatted or you only care about attributes

## Comparison: Basic vs Context Scanner

| Feature | `scan_with_plugins.py` | `scan_xml_with_context.py` |
|---------|------------------------|----------------------------|
| Speed | Fast | Slower (parses XML) |
| Multi-line support | ❌ No | ✅ Yes |
| Parent element | ❌ No | ✅ Yes |
| Element path | ❌ No | ✅ Yes |
| XML attributes | ✅ Yes | ✅ Yes |
| Single-line elements | ✅ Yes | ✅ Yes |
| Malformed XML | May scan anyway | ❌ Skips |

## Examples

### Scan with Full Context

```bash
# Scan samples with context
python3 scan_xml_with_context.py samples --output context_results.json

# View results
python3 << 'EOF'
import json
with open('context_results.json') as f:
    data = json.load(f)

for secret in data['secrets']:
    print(f"Path: {secret['element_path']}")
    print(f"Secret: {secret['secret'][:30]}...")
    print()
EOF
```

### Production Secrets with Context

```bash
python3 scan_xml_with_context.py /path/to/repo \
  --prod-only \
  --output prod_context.json

# Generate report
python3 << 'EOF'
import json
with open('prod_context.json') as f:
    data = json.load(f)

print("Production Secrets Report")
print("=" * 60)

# Group by parent element
from collections import defaultdict
by_element = defaultdict(list)

for s in data['secrets']:
    by_element[s['parent_element']].append(s)

for element, secrets in sorted(by_element.items()):
    print(f"\n{element}: {len(secrets)} secret(s)")
    for s in secrets:
        print(f"  {s['element_path']}")
EOF
```

### Find Database Credentials

```bash
python3 scan_xml_with_context.py /path/to/repo \
  --include-entities "database_.*" "db_.*" "connection.*" \
  --output db_creds.json

# Show just database secrets
python3 -c "
import json
data = json.load(open('db_creds.json'))
for s in data['secrets']:
    if 'database' in s['element_path'].lower():
        print(f'{s[\"element_path\"]}: {s[\"secret\"][:20]}...')
"
```

## Best Practices

1. **Use context scanner for comprehensive audits**
   ```bash
   python3 scan_xml_with_context.py /path/to/repo --output audit.json
   ```

2. **Use basic scanner for quick checks**
   ```bash
   python3 scan_with_plugins.py /path/to/repo --output quick.json
   ```

3. **Enable normalization by default**
   - Only use `--no-normalize` if you're sure XML is single-line

4. **Use element paths for filtering**
   - Review `element_path` to understand secret location
   - Use parent element to group related secrets

5. **Compare both scanners**
   ```bash
   # Basic scan
   python3 scan_with_plugins.py samples --output basic.json

   # Context scan
   python3 scan_xml_with_context.py samples --output context.json

   # Compare counts
   echo "Basic: $(jq '.total_secrets_found' basic.json)"
   echo "Context: $(jq '.total_secrets_found' context.json)"
   ```

## Troubleshooting

### XML Parsing Errors

**Problem:** `Error parsing XML: not well-formed`

**Solution:**
- Check XML is valid
- Look for special characters in comments
- Use XML validator: `xmllint --noout file.xml`

### Missing Secrets

**Problem:** Known secrets not detected

**Solution:**
```bash
# Try without normalization
python3 scan_xml_with_context.py file.xml --no-normalize

# Check if filters are excluding it
python3 scan_xml_with_context.py file.xml --min-length 3

# Scan without any filters first
python3 scan_xml_with_context.py file.xml
```

### Slow Performance

**Problem:** Scanning takes too long

**Solution:**
```bash
# Disable normalization
python3 scan_xml_with_context.py /repo --no-normalize

# Or use basic scanner for quick checks
python3 scan_with_plugins.py /repo
```

## When to Use Which Scanner

### Use `scan_xml_with_context.py` When:
- ✅ XML has multi-line elements
- ✅ Need parent element information
- ✅ Want element path in output
- ✅ Doing comprehensive audit
- ✅ Need to understand secret context

### Use `scan_with_plugins.py` When:
- ✅ XML is already single-line formatted
- ✅ Need fast scanning
- ✅ Only scanning attributes
- ✅ Quick check for obvious secrets
- ✅ Scanning non-XML files

## Summary

The **XML Context Scanner** (`scan_xml_with_context.py`) provides:

1. ✅ Multi-line XML support via normalization
2. ✅ Parent element context in output
3. ✅ Full element path (XPath-like)
4. ✅ Detection method (element_value vs attribute)
5. ✅ All filtering options from basic scanner

**Recommended for production use when scanning XML repositories!**
