# Ignore Values Guide

## Overview

The scanner automatically ignores common false positives like boolean values (`true`, `false`), null values (`null`, `none`, `nil`), and configuration values (`enabled`, `disabled`, `yes`, `no`). You can also add custom values to ignore.

## Default Ignored Values

The following values are **automatically ignored** (case-insensitive):

### Boolean Values
- `true`, `false`
- `yes`, `no`
- `on`, `off`
- `enabled`, `disabled`

### Null/Empty Values
- `null`, `none`, `nil`, `undefined`
- `empty`, `blank`, `default`

### Common Placeholders
- `password`, `changeme`, `example`, `test`, `sample`
- `placeholder`, `xxx`, `****`
- `your_password_here`, `enter_password`, `your_password`, `insert_password`
- `admin`, `123456`, `qwerty`, `letmein`

### Configuration Values
- `default`, `empty`, `blank`
- `n/a`, `na`, `tbd`

### Single Characters/Digits
- Single characters: `a`, `b`, `c`, `x`, `y`, `z`
- Single digits: `0`, `1`, `-1`

## Example: Default Ignore Behavior

Given this XML:
```xml
<configuration>
    <enabled>true</enabled>
    <debug>false</debug>
    <password>null</password>
    <api_key>undefined</api_key>
    <setting>yes</setting>
    <password>MyRealPassword123!</password>
</configuration>
```

**Result:** Only `MyRealPassword123!` is detected. The boolean and null values are automatically ignored.

## Adding Custom Ignore Values

Use `--ignore-values` to add your own values to ignore.

### CLI Usage

```bash
# Ignore specific values
python3 scan_with_plugins.py /path/to/repo --ignore-values "myapp" "config123" "localhost"

# Ignore application-specific values
python3 scan_xml_with_context.py /path/to/repo \
  --ignore-values "MyAppName" "default_user" "example_com" \
  --output results.json
```

### Example Scenarios

**Scenario 1: Application-specific defaults**
```bash
# Ignore your application name and common test values
python3 scan_with_plugins.py /repo --ignore-values "MyApplication" "testuser" "localhost"
```

**Scenario 2: Known test/dummy values**
```bash
# Ignore known test credentials
python3 scan_with_plugins.py /repo --ignore-values "test123" "dummy_key" "sample_token"
```

**Scenario 3: Environment-specific values**
```bash
# Ignore dev environment identifiers
python3 scan_with_plugins.py /repo --ignore-values "dev" "staging" "local"
```

## Python API Usage

```python
from xml_plugins import XMLPasswordPlugin

# Create plugin with custom ignore values
plugin = XMLPasswordPlugin(
    ignore_values=['myapp', 'config123', 'localhost', 'testvalue']
)

# Scan a file
with open('config.xml') as f:
    for line_num, line in enumerate(f, 1):
        for secret in plugin.analyze_line('config.xml', line, line_num):
            print(f"Line {line_num}: {secret.secret_value}")
```

## Case Sensitivity

**All ignore values are case-insensitive:**

```bash
# This will ignore "MyApp", "myapp", "MYAPP", "MyApP", etc.
python3 scan_with_plugins.py /repo --ignore-values "myapp"
```

Example:
```xml
<password>MyApp</password>   <!-- Ignored -->
<password>myapp</password>   <!-- Ignored -->
<password>MYAPP</password>   <!-- Ignored -->
```

## Combining with Other Filters

You can combine `--ignore-values` with other filtering options:

```bash
# Scan production secrets only, ignoring specific values
python3 scan_with_plugins.py /repo \
  --prod-only \
  --ignore-values "myapp" "testvalue" \
  --output results.json

# Scan specific entities, ignoring common false positives
python3 scan_with_plugins.py /repo \
  --include-entities "database_.*" "api_.*" \
  --ignore-values "localhost" "127.0.0.1" "default_db" \
  --output results.json
```

## Plugin Manager Usage

When using the PluginManager directly:

```python
from plugin_manager import PluginManager

# Create plugin manager with custom ignore values
plugin_manager = PluginManager(
    xml_password_config={
        'ignore_values': ['myapp', 'config123', 'localhost'],
        'min_password_length': 6
    }
)

# Scan with all plugins
for secret in plugin_manager.scan_line('config.xml', line, line_num):
    print(f"Found: {secret.secret_value}")
```

## Real-World Example

**Before** (with false positives):
```bash
$ python3 scan_with_plugins.py /repo --output results.json

Found 47 secrets:
- true (false positive)
- false (false positive)
- enabled (false positive)
- null (false positive)
- myapp (false positive - application name)
- localhost (false positive - test value)
- RealPassword123! (real secret) ✓
- ... 40 more false positives
```

**After** (with ignore values):
```bash
$ python3 scan_with_plugins.py /repo \
  --ignore-values "myapp" "localhost" \
  --output results.json

Found 1 secret:
- RealPassword123! (real secret) ✓
```

## Common Use Cases

### 1. Ignore Application Name

If your application name appears in configs and gets flagged:

```bash
python3 scan_with_plugins.py /repo --ignore-values "MyApplicationName"
```

### 2. Ignore Test/Example Values

```bash
python3 scan_with_plugins.py /repo --ignore-values \
  "test123" "example" "sample" "demo" "testuser"
```

### 3. Ignore Local Development Values

```bash
python3 scan_with_plugins.py /repo --ignore-values \
  "localhost" "127.0.0.1" "local" "dev" "development"
```

### 4. Ignore Known Safe Passwords

```bash
# For test environments where certain passwords are known and safe
python3 scan_with_plugins.py /test/configs --ignore-values \
  "test_password_123" "dev_secret" "local_key"
```

## Template Variables and Environment Variables

Template variables and environment variable references are **automatically ignored** without needing `--ignore-values`:

```xml
<!-- These are automatically ignored -->
<password>${PASSWORD}</password>
<api_key>{{API_KEY}}</api_key>
<secret>$ENV_VAR</secret>
<password>%PASSWORD%</password>
```

## EXAMPLE Values

Any value containing "EXAMPLE" is **automatically ignored**:

```xml
<!-- These are automatically ignored -->
<password>EXAMPLE_PASSWORD</password>
<api_key>AWS_KEY_EXAMPLE</api_key>
<secret>EXAMPLE_SECRET_VALUE</secret>
```

## Best Practices

### ✅ DO
- Add application-specific values that are always safe
- Add known test/dummy values
- Add environment identifiers that aren't secrets
- Use case-insensitive matching (already built-in)
- Combine with `--prod-only` for production scans

### ❌ DON'T
- Add real secrets to ignore list
- Add overly broad patterns that might miss real secrets
- Rely solely on ignore values - also use entity/attribute filtering

## Troubleshooting

### Problem: Still seeing false positives

**Solution 1:** Add them to ignore values
```bash
python3 scan_with_plugins.py /repo --ignore-values "false_positive_value"
```

**Solution 2:** Use entity filtering
```bash
# Exclude test entities entirely
python3 scan_with_plugins.py /repo --exclude-entities "test_.*" "example_.*"
```

**Solution 3:** Increase minimum length
```bash
# Only detect passwords 8+ characters
python3 scan_with_plugins.py /repo --min-length 8
```

### Problem: Real secret being ignored

**Check if it matches a default ignore value:**
```bash
# List all default ignore values
python3 -c "from xml_plugins import XMLPasswordPlugin; print(XMLPasswordPlugin().placeholder_values)"
```

**Workaround:** Rename the secret in your configuration if it matches a placeholder.

## Testing Ignore Values

Run the test suite to verify ignore values work correctly:

```bash
python3 test_ignore_values.py
```

Expected output:
```
✓ PASS - Default Ignore Values
✓ PASS - Custom Ignore Values
✓ PASS - Ignore Values in Attributes
Total: 3/3 test suites passed
```

## Summary

- **Default:** Boolean values, null values, placeholders, and config values are automatically ignored
- **Custom:** Use `--ignore-values` to add application-specific values
- **Case-insensitive:** "MyApp", "myapp", and "MYAPP" are all ignored
- **Combines:** Works with all other filtering options (`--prod-only`, `--include-entities`, etc.)
- **Safe:** Template variables and EXAMPLE values are automatically excluded

This feature dramatically reduces false positives while maintaining high detection accuracy for real secrets.
