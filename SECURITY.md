# Security Considerations

## Important: This Tool Outputs Actual Secrets

Unlike vanilla detect-secrets which only shows hashed values, **xml-secrets-scanner outputs the actual detected secret values** in JSON format for verification purposes.

⚠️ **CRITICAL:** Never commit output files to version control!

## Files That Contain Secrets

### Output Files (NEVER COMMIT)

All these files contain actual secret values and are automatically ignored by `.gitignore`:

```
*results.json          # Any file ending in results.json
*-results.json         # Example: scan-results.json
*_results.json         # Example: prod_results.json
*-secrets.json         # Example: found-secrets.json
*-scan.json            # Example: daily-scan.json
audit-*.json           # Example: audit-2024.json
prod-*.json            # Example: prod-findings.json
demo_*.json            # Example: demo_output.json
context_*.json         # Example: context_scan.json
*.normalized.xml       # Normalized XML may expose secrets
*.log                  # Logs may contain secret values
```

### Safe Files (OK to Commit)

These files contain **fake secrets for testing** and are safe to commit:

```
samples/*.xml          # Test XML files with fake secrets
test_examples.xml      # Example test data
.secrets.baseline      # detect-secrets baseline (no actual secrets)
```

## .gitignore Configuration

The `.gitignore` file is configured with multiple layers of protection:

### Layer 1: Pattern Matching
Ignores all common output file patterns that contain secrets.

### Layer 2: Explicit Exceptions
Allows specific safe files (like samples) to be committed.

### Layer 3: Additional Safeguards
Ignores any file with SENSITIVE, SECRET, or PRIVATE in the name.

## Best Practices

### 1. Always Use --output Flag

```bash
# Good - saves to file (which is gitignored)
python3 scan_xml_with_context.py /repo --output results.json

# Bad - prints to stdout (could be accidentally saved)
python3 scan_xml_with_context.py /repo > output.txt
```

### 2. Store Results Outside Repository

```bash
# Store results outside the repo
python3 scan_xml_with_context.py /path/to/repo \
  --output ~/security-audits/scan-$(date +%Y%m%d).json
```

### 3. Encrypt Results If Needed

```bash
# Encrypt sensitive scan results
python3 scan_xml_with_context.py /repo --output results.json
gpg --encrypt --recipient your@email.com results.json
rm results.json  # Remove unencrypted version
```

### 4. Use Secure Channels for Sharing

❌ **Never:**
- Email unencrypted results
- Paste results in Slack/Teams
- Commit results to git
- Store in unencrypted cloud storage

✅ **Do:**
- Use encrypted email attachments
- Share via secure file transfer
- Store in encrypted storage
- Use temporary secure sharing services

### 5. Clean Up After Scans

```bash
# Run scan
python3 scan_xml_with_context.py /repo --output results.json

# Review results
cat results.json | jq '.secrets[] | {file, element_path, type}'

# Clean up immediately
shred -u results.json  # Linux/Mac
# or
rm -P results.json     # Mac
```

## Verifying .gitignore

Before committing, verify no secrets will be exposed:

```bash
# Check what would be committed
git add -n .

# Verify no JSON result files are included
git status | grep -i "json"

# Double-check ignored files
git status --ignored | grep -E "\.json$"
```

## If Secrets Are Accidentally Committed

### Step 1: Remove from Git History

```bash
# Remove file from history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch results.json" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (if already pushed)
git push origin --force --all
```

### Step 2: Rotate Exposed Secrets

If real secrets were committed:
1. **Immediately rotate all exposed credentials**
2. Update passwords, API keys, tokens
3. Review access logs for unauthorized use
4. Document the incident

### Step 3: Use BFG Repo-Cleaner (Alternative)

```bash
# Download BFG
# https://rtyley.github.io/bfg-repo-cleaner/

# Remove all files matching pattern
bfg --delete-files "*.json" --no-blob-protection

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

## Scanning Third-Party Code

When scanning repositories you don't control:

### 1. Clone to Temporary Location

```bash
# Clone to temp directory
git clone https://github.com/org/repo /tmp/audit-$(date +%s)
cd /tmp/audit-*

# Scan
python3 /path/to/xml-secrets-scanner/scan_xml_with_context.py . \
  --output ~/secure/audit-results.json

# Clean up clone
cd ~
rm -rf /tmp/audit-*
```

### 2. Never Commit Scan Results to Their Repo

```bash
# Add to .git/info/exclude (not tracked by git)
echo "*results.json" >> .git/info/exclude
echo "*.log" >> .git/info/exclude
```

## Sample Files Security

The `samples/` directory contains XML files with **fake secrets** for testing:

### These Are Safe to Commit:
- `samples/prod_database_config.xml` - Fake production credentials
- `samples/test_database_config.xml` - Fake test credentials
- `samples/mixed_config.xml` - Fake mixed credentials

### Why They're Safe:
- All passwords are obviously fake (e.g., "P@ssw0rd_Pr0duction_2024!")
- All API keys are example format (e.g., "AIzaSyD-Pr0dK3y...")
- Unix crypt hashes are synthetic
- Used only for testing detection capabilities

**Never replace sample files with real production data!**

## Responsible Disclosure

If you discover secrets in a public repository:

1. **Do not publish the secrets**
2. Contact the repository owner privately
3. Use GitHub Security Advisories if available
4. Give them time to rotate credentials (typically 90 days)
5. Follow coordinated disclosure practices

## Compliance

When using this tool for compliance purposes:

### PCI DSS
- Scan results contain secrets → treat as sensitive data
- Store encrypted
- Limit access (need-to-know basis)
- Audit access to results

### GDPR
- If credentials relate to individuals, GDPR may apply
- Document data retention policy
- Delete scan results after review

### SOC 2
- Maintain audit trail of scans
- Document remediation of findings
- Secure storage of results

## Summary

✅ **Do:**
- Use `.gitignore` (already configured)
- Store results outside repository
- Encrypt sensitive results
- Clean up after scans
- Verify before committing

❌ **Never:**
- Commit `*results.json` files
- Share unencrypted results
- Email scan outputs
- Store in public locations
- Replace samples with real data

The `.gitignore` is configured to protect you, but always double-check before committing!
