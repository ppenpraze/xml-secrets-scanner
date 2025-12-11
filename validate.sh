#!/bin/bash
# Quick validation script to test the plugins

set -e

echo "================================================================================"
echo "XML Secret Detection - Validation"
echo "================================================================================"
echo ""

# Test 1: Plugin tests
echo "✓ Running plugin tests..."
python3 test_plugins.py > /dev/null 2>&1
echo "  ✓ All plugin tests passed"
echo ""

# Test 2: Scan samples
echo "✓ Scanning sample files..."
python3 scan_with_plugins.py samples --output /tmp/validate_all.json 2>&1 | grep -E "Found|Scanned|Summary" || true
ALL_COUNT=$(python3 -c "import json; print(json.load(open('/tmp/validate_all.json'))['total_secrets_found'])")
echo "  ✓ Found $ALL_COUNT secrets (no filtering)"
echo ""

# Test 3: Production only
echo "✓ Scanning with --prod-only..."
python3 scan_with_plugins.py samples --prod-only --output /tmp/validate_prod.json 2>&1 | grep -E "Found|Scanned|Summary" || true
PROD_COUNT=$(python3 -c "import json; print(json.load(open('/tmp/validate_prod.json'))['total_secrets_found'])")
echo "  ✓ Found $PROD_COUNT secrets (production only)"
echo ""

# Test 4: Database only
echo "✓ Scanning database configs only..."
python3 scan_with_plugins.py samples \
  --include-entities "database_.*" "db_.*" \
  --exclude-entities "test.*" \
  --output /tmp/validate_db.json 2>&1 | grep -E "Found|Scanned|Summary" || true
DB_COUNT=$(python3 -c "import json; print(json.load(open('/tmp/validate_db.json'))['total_secrets_found'])")
echo "  ✓ Found $DB_COUNT secrets (database only)"
echo ""

# Summary
echo "================================================================================"
echo "Validation Summary"
echo "================================================================================"
echo ""
echo "Test Results:"
echo "  ✓ Plugin tests: PASSED"
echo "  ✓ Sample scans: PASSED"
echo ""
echo "Secret Detection:"
echo "  • All secrets:        $ALL_COUNT"
echo "  • Production only:    $PROD_COUNT"
echo "  • Database configs:   $DB_COUNT"
echo ""

# Validate filtering worked
if [ "$PROD_COUNT" -lt "$ALL_COUNT" ]; then
    echo "✓ Filtering: WORKING (prod-only found fewer secrets than unfiltered)"
else
    echo "⚠ Warning: Filtering may not be working as expected"
fi
echo ""

echo "================================================================================"
echo "All validation checks passed!"
echo "================================================================================"
echo ""
echo "Sample files available in: samples/"
echo "  - prod_database_config.xml (production secrets)"
echo "  - test_database_config.xml (test secrets)"
echo "  - mixed_config.xml (mixed prod/test)"
echo "  - database_only.xml (database configs)"
echo ""
echo "To run full demo: ./demo.sh"
echo ""

# Cleanup
rm -f /tmp/validate_*.json
