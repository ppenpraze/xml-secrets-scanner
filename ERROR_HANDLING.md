# Error Handling & Non-XML Files

This document explains how the scanners handle malformed XML, broken files, and non-XML text formats.

## Scanner Behavior

### scan_xml_with_context.py (XML Parser)

**How it handles errors:**

1. **Malformed XML** → Skips file, reports error, continues
2. **Invalid characters** → Skips file, reports error, continues
3. **Missing closing tags** → Skips file, reports error, continues
4. **Non-XML files** → Skips file, reports error, continues

**Example output:**
```
Error parsing XML: not well-formed (invalid token): line 2, column 77
Error parsing samples/broken.xml: not well-formed (invalid token): line 2, column 77
```

**What happens:**
- File is **skipped** entirely
- Error message is printed to stderr
- Scanning continues with next file
- Exit code is still 1 if any secrets found in valid files

### scan_with_plugins.py (Line-Based Scanner)

**How it handles errors:**

1. **Malformed XML** → Scans anyway (line-by-line)
2. **Invalid characters** → Ignores encoding errors
3. **Missing closing tags** → Doesn't care (regex-based)
4. **Non-XML files** → Scans anyway (works on any text)

**What happens:**
- File is scanned line-by-line
- Uses `errors='ignore'` for encoding issues
- Regex patterns still work on malformed XML
- May detect secrets that XML parser would miss

## Common XML Issues

### Issue 1: Double Hyphens in Comments

**Invalid XML:**
```xml
<!-- This uses --prod-only flag -->
```

**Error:**
```
not well-formed (invalid token): line 2, column 77
```

**Why:** XML comments cannot contain `--` except at the end (`-->`)

**Fix:**
```xml
<!-- This uses prod-only flag -->
<!-- This uses -prod-only flag -->
<!-- This uses 'prod-only' flag -->
```

### Issue 2: Unescaped Special Characters

**Invalid XML:**
```xml
<password>Secret&Password</password>
```

**Error:**
```
not well-formed (invalid token)
```

**Fix:**
```xml
<password>Secret&amp;Password</password>
```

### Issue 3: Missing Closing Tags

**Invalid XML:**
```xml
<configuration>
    <password>secret</password>
<!-- Missing </configuration> -->
```

**Error:**
```
no element found
```

**Fix:** Add closing tags

### Issue 4: Encoding Issues

**Invalid XML:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<password>Café™</password>  <!-- Wrong encoding -->
```

**Error:**
```
not well-formed (invalid token)
```

**Fix:** Use proper encoding or escape characters

## Handling Non-XML Files

### Configuration Files (.properties, .ini, .conf)

**Use line-based scanner:**
```bash
python3 scan_with_plugins.py /path/to/configs \
  --extensions .properties .ini .conf \
  --output results.json
```

**Example .properties file:**
```properties
database.password=MySecret123
api.key=AIzaSy...
```

**Detection:** Works! Line-based scanner detects `password=` and `key=` patterns.

### JSON Files

**Use line-based scanner:**
```bash
python3 scan_with_plugins.py /path/to/configs \
  --extensions .json \
  --output results.json
```

**Example:**
```json
{
  "password": "MySecret123",
  "api_key": "AIzaSy..."
}
```

**Detection:** Works with line-based scanner.

### YAML Files

**Use line-based scanner:**
```bash
python3 scan_with_plugins.py /path/to/configs \
  --extensions .yaml .yml \
  --output results.json
```

**Example:**
```yaml
database:
  password: MySecret123
  host: localhost
```

**Detection:** Works with line-based scanner.

## Strategies for Malformed XML

### Strategy 1: Fix the XML

```bash
# Use xmllint to identify issues
xmllint --noout yourfile.xml

# Fix issues, then scan
python3 scan_xml_with_context.py yourfile.xml
```

### Strategy 2: Use Line-Based Scanner

```bash
# Scan as-is, line-by-line
python3 scan_with_plugins.py /path/to/broken-xml \
  --output results.json
```

**Pros:**
- Works on malformed XML
- Works on any text format
- Faster

**Cons:**
- No parent element context
- May miss multi-line secrets
- Less accurate

### Strategy 3: Pre-process XML

```bash
# Try to fix XML automatically
xmllint --recover yourfile.xml > fixed.xml

# Then scan
python3 scan_xml_with_context.py fixed.xml
```

### Strategy 4: Scan Both Ways

```bash
# XML parser (for valid XML)
python3 scan_xml_with_context.py /path/to/repo \
  --output context_results.json

# Line-based (for all files, including malformed)
python3 scan_with_plugins.py /path/to/repo \
  --output line_results.json

# Compare
echo "Context scanner: $(jq '.total_secrets_found' context_results.json)"
echo "Line scanner: $(jq '.total_secrets_found' line_results.json)"
```

## Best Practices

### 1. Validate XML First

```bash
# Check XML validity
find /path/to/repo -name "*.xml" -exec xmllint --noout {} \; 2>&1 | grep -v "validates"

# Or with Python
python3 << 'EOF'
import xml.etree.ElementTree as ET
from pathlib import Path

for xml_file in Path('/path/to/repo').rglob('*.xml'):
    try:
        ET.parse(xml_file)
        print(f"✓ {xml_file}")
    except ET.ParseError as e:
        print(f"✗ {xml_file}: {e}")
EOF
```

### 2. Use Appropriate Scanner

| File Type | Recommended Scanner |
|-----------|---------------------|
| Valid XML | `scan_xml_with_context.py` |
| Malformed XML | `scan_with_plugins.py` |
| .properties | `scan_with_plugins.py` |
| .json | `scan_with_plugins.py` |
| .yaml | `scan_with_plugins.py` |
| .ini | `scan_with_plugins.py` |
| Mixed formats | `scan_with_plugins.py` |

### 3. Handle Errors Gracefully

The scanners are designed to:
- **Continue on errors** - One bad file doesn't stop the scan
- **Report errors** - You know which files failed
- **Process valid files** - Still get results from working files

### 4. Review Error Messages

```bash
# Separate errors from results
python3 scan_xml_with_context.py /path/to/repo \
  --output results.json \
  2> errors.log

# Review errors
cat errors.log

# Count failed files
grep "Error parsing" errors.log | wc -l
```

## Troubleshooting

### Problem: Files Skipped Due to Parse Errors

**Symptoms:**
```
Error parsing XML: not well-formed (invalid token)
Error parsing samples/config.xml: not well-formed
```

**Solutions:**

1. **Fix the XML:**
   ```bash
   xmllint --recover config.xml > fixed.xml
   ```

2. **Use line-based scanner:**
   ```bash
   python3 scan_with_plugins.py samples --output results.json
   ```

3. **Identify the issue:**
   ```bash
   xmllint --noout config.xml
   ```

### Problem: Want to Scan All Files Regardless of Format

**Solution:** Use line-based scanner with multiple extensions:

```bash
python3 scan_with_plugins.py /path/to/repo \
  --extensions .xml .json .yaml .properties .conf .ini \
  --output results.json
```

### Problem: Mixed Valid and Invalid XML

**Solution:** Scan both ways and merge results:

```bash
# Context scanner (valid XML only)
python3 scan_xml_with_context.py /path/to/repo \
  --output valid_xml.json \
  2> xml_errors.log

# Line scanner (all files)
python3 scan_with_plugins.py /path/to/repo \
  --output all_files.json

# Check which files failed XML parsing
cat xml_errors.log
```

## Summary

### scan_xml_with_context.py
- ✅ Best for **valid XML**
- ✅ Provides **parent element context**
- ❌ **Skips malformed XML**
- ❌ **XML files only**

### scan_with_plugins.py
- ✅ Works on **any text format**
- ✅ Handles **malformed XML**
- ✅ **Faster** (no parsing)
- ❌ No parent element context
- ❌ May miss multi-line secrets

### Recommendation

1. **Try XML parser first** - Get parent element context
2. **Check error messages** - See which files failed
3. **Use line scanner for failures** - Catch secrets in malformed files
4. **Fix XML if possible** - Best long-term solution

Both scanners are designed to **fail gracefully** and continue processing, so you always get results from the files that can be scanned.
