# Sample XML Files for Testing

This directory contains sample XML configuration files to demonstrate the secret detection capabilities.

## Files

### 1. prod_database_config.xml
**Production database configuration with real secrets**

Contains:
- ✅ Production database passwords (`prod_password`)
- ✅ Production API keys (`production_credentials`)
- ✅ Live API endpoints (`live_api_key`, `live_secret`)
- ✅ Unix crypt hashes (SHA-512, bcrypt)

**Expected behavior:**
- Detected with `--prod-only`
- Contains 8+ secrets

### 2. test_database_config.xml
**Test/development configuration (should be filtered)**

Contains:
- ❌ Test passwords (`test_password`)
- ❌ Dev credentials (`dev_password`, `dev_api_key`)
- ❌ Example placeholders (`example_password`, `sample_password`)
- ❌ Placeholder values (`password`, `changeme`)

**Expected behavior:**
- EXCLUDED with `--prod-only`
- Detected without filtering

### 3. mixed_config.xml
**Mixed production and test configuration**

Contains:
- ✅ Production secrets (detected with `--prod-only`)
- ❌ Test secrets (filtered with `--prod-only`)
- ✅ AWS credentials
- ✅ API keys (Google Maps, Stripe)

**Expected behavior:**
- With `--prod-only`: Only production secrets
- Without filtering: All secrets

### 4. database_only.xml
**Database-specific configuration**

Contains:
- Database passwords with `database_` prefix
- Mix of production and test database credentials

**Expected behavior:**
- Useful for testing `--include-entities "database_.*"`

## Testing Commands

### Scan All Samples
```bash
python3 scan_with_plugins.py samples --output all_results.json
```

### Production Secrets Only
```bash
python3 scan_with_plugins.py samples --prod-only --output prod_results.json
```

### Database Configurations Only
```bash
python3 scan_with_plugins.py samples \
  --include-entities "database_.*" "db_.*" \
  --exclude-entities "test.*" \
  --output db_results.json
```

### Custom Filtering
```bash
# Only API keys
python3 scan_with_plugins.py samples \
  --include-attributes "api_key" "secret_key" \
  --output api_keys.json

# Exclude test and dev
python3 scan_with_plugins.py samples \
  --exclude-entities "test_.*" "dev_.*" "example_.*" \
  --output filtered.json
```

## Expected Results

### Without Filtering (scan everything)
**Expected secrets found:** ~15-20

**Types:**
- XML Passwords in production configs
- XML Passwords in test configs
- Unix Crypt Hashes
- API keys and secrets

### With `--prod-only`
**Expected secrets found:** ~8-12

**Types:**
- Only production/live secrets
- No test/dev/example data

**Filtered out:**
- test_password
- dev_password
- example_password
- sample_password
- Placeholder values

## Validation Checklist

Use these samples to validate the plugins work correctly:

- [ ] `--prod-only` excludes all test/dev/example secrets
- [ ] `--prod-only` includes all prod/production/live secrets
- [ ] Unix crypt hashes are detected (SHA-512, bcrypt)
- [ ] Placeholder values are filtered (password, changeme, etc.)
- [ ] Custom `--include-entities` filters work correctly
- [ ] Custom `--exclude-entities` filters work correctly
- [ ] `min_password_length` filters short passwords
- [ ] JSON output includes actual secret values
- [ ] Line numbers are accurate

## Demo Script

Run the comprehensive demo:
```bash
./demo.sh
```

This will:
1. Run plugin tests
2. Scan all samples without filtering
3. Scan with `--prod-only`
4. Scan database configs only
5. Demonstrate Python API usage
6. Generate example output files

## Output Files

The demo script creates:
- `demo_all.json` - All secrets (no filtering)
- `demo_prod.json` - Production secrets only
- `demo_database.json` - Database configs only

View results:
```bash
# Pretty print all results
cat demo_all.json | jq .

# Show just the secrets
cat demo_prod.json | jq '.secrets[]'

# Count secrets
cat demo_all.json | jq '.total_secrets_found'
```

## Creating Your Own Samples

To create test data for your specific use case:

1. **Use your naming convention:**
   ```xml
   <your_prod_prefix_password>secret</your_prod_prefix_password>
   ```

2. **Test filtering:**
   ```bash
   python3 scan_with_plugins.py samples \
     --include-entities "your_prod_prefix_.*" \
     --exclude-entities "your_test_prefix_.*"
   ```

3. **Validate results match expectations**

## Security Note

⚠️ These sample files contain **fake** secrets for testing purposes only. Do not use these secrets in any real system.
