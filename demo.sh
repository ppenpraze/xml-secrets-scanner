#!/bin/bash

# XML Secret Detection - Demo Script
# This script demonstrates how to use the detect-secrets plugins

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "================================================================================"
echo "XML Secret Detection - Demo"
echo "================================================================================"
echo ""

# Check if plugins are installed
echo -e "${BLUE}Checking installation...${NC}"
if ! python3 -c "import xml_plugins" 2>/dev/null; then
    echo -e "${YELLOW}Installing plugins...${NC}"
    pip install -e . > /dev/null 2>&1
    echo -e "${GREEN}✓ Plugins installed${NC}"
else
    echo -e "${GREEN}✓ Plugins already installed${NC}"
fi
echo ""

# Run tests
echo "================================================================================"
echo -e "${BLUE}1. Running Plugin Tests${NC}"
echo "================================================================================"
python3 test_plugins.py
echo ""

# Demo 1: Scan all samples (no filtering)
echo "================================================================================"
echo -e "${BLUE}2. Demo: Scan All Samples (No Filtering)${NC}"
echo "================================================================================"
echo -e "${YELLOW}Command:${NC} python3 scan_with_plugins.py samples --output demo_all.json"
echo ""
python3 scan_with_plugins.py samples --output demo_all.json
echo ""
echo -e "${GREEN}Results saved to: demo_all.json${NC}"
echo -e "${YELLOW}Summary:${NC}"
jq -r '.secrets[] | "  - \(.file):\(.line_number) - \(.type)"' demo_all.json 2>/dev/null || cat demo_all.json
echo ""

# Demo 2: Scan production secrets only
echo "================================================================================"
echo -e "${BLUE}3. Demo: Scan Production Secrets Only (--prod-only)${NC}"
echo "================================================================================"
echo -e "${YELLOW}Command:${NC} python3 scan_with_plugins.py samples --prod-only --output demo_prod.json"
echo ""
python3 scan_with_plugins.py samples --prod-only --output demo_prod.json 2>&1 || true
echo ""
echo -e "${GREEN}Results saved to: demo_prod.json${NC}"
echo -e "${YELLOW}Summary (only production secrets detected):${NC}"
jq -r '.secrets[] | "  - \(.file):\(.line_number) - \(.type): \(.secret[:50])"' demo_prod.json 2>/dev/null || cat demo_prod.json
echo ""

# Demo 3: Scan database configs only
echo "================================================================================"
echo -e "${BLUE}4. Demo: Scan Database Configurations Only${NC}"
echo "================================================================================"
echo -e "${YELLOW}Command:${NC} python3 scan_with_plugins.py samples \\"
echo "  --include-entities 'database_.*' 'db_.*' \\"
echo "  --exclude-entities 'test.*' 'dev.*' \\"
echo "  --output demo_database.json"
echo ""
python3 scan_with_plugins.py samples \
  --include-entities "database_.*" "db_.*" \
  --exclude-entities "test.*" "dev.*" \
  --output demo_database.json 2>&1 || true
echo ""
echo -e "${GREEN}Results saved to: demo_database.json${NC}"
echo -e "${YELLOW}Summary (only database secrets):${NC}"
jq -r '.secrets[] | "  - \(.file):\(.line_number) - \(.type)"' demo_database.json 2>/dev/null || cat demo_database.json
echo ""

# Demo 4: Python API usage
echo "================================================================================"
echo -e "${BLUE}5. Demo: Python API Usage${NC}"
echo "================================================================================"
cat << 'EOF' > /tmp/demo_api.py
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin
from pathlib import Path

print("Using Python API to scan samples/prod_database_config.xml")
print("-" * 60)

xml_plugin = XMLPasswordPlugin(
    include_entities=['prod_.*', 'production_.*'],
    exclude_entities=['test_.*', 'dev_.*'],
    min_password_length=6
)

unix_plugin = UnixCryptPlugin()

file_path = 'samples/prod_database_config.xml'
if Path(file_path).exists():
    with open(file_path) as f:
        for line_num, line in enumerate(f, 1):
            # Check for XML passwords
            for secret in xml_plugin.analyze_line(file_path, line, line_num):
                print(f"Line {line_num:3d}: {secret.type:20s} = {secret.secret_value[:50]}")

            # Check for Unix crypt hashes
            for secret in unix_plugin.analyze_line(file_path, line, line_num):
                print(f"Line {line_num:3d}: {secret.type:20s} = {secret.secret_value[:50]}")
else:
    print("File not found!")
EOF

python3 /tmp/demo_api.py
echo ""

# Summary
echo "================================================================================"
echo -e "${GREEN}Demo Complete!${NC}"
echo "================================================================================"
echo ""
echo "Output files created:"
echo "  - demo_all.json       : All secrets (no filtering)"
echo "  - demo_prod.json      : Production secrets only"
echo "  - demo_database.json  : Database configurations only"
echo ""
echo "Sample files scanned:"
echo "  - samples/prod_database_config.xml  : Production database config"
echo "  - samples/test_database_config.xml  : Test/dev database config"
echo "  - samples/mixed_config.xml          : Mixed prod/test config"
echo "  - samples/database_only.xml         : Database-specific config"
echo ""
echo -e "${YELLOW}To view detailed results:${NC}"
echo "  cat demo_all.json | jq ."
echo "  cat demo_prod.json | jq '.secrets[]'"
echo ""
echo -e "${YELLOW}To run your own scan:${NC}"
echo "  python3 scan_with_plugins.py /path/to/repo --output results.json"
echo "  python3 scan_with_plugins.py /path/to/repo --prod-only"
echo ""
echo -e "${GREEN}For more examples, see:${NC}"
echo "  - README.md"
echo "  - README_PLUGINS.md"
echo "  - QUICK_REFERENCE.md"
echo ""
