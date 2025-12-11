#!/usr/bin/env python3
"""
Direct test of custom plugins without detect-secrets CLI.
"""

from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin

def test_xml_password_plugin():
    """Test XMLPasswordPlugin"""
    print("=== Testing XMLPasswordPlugin ===\n")

    plugin = XMLPasswordPlugin()

    test_lines = [
        '<password>SuperSecret123!</password>',
        '<server password="MyP@ssw0rd2024" ip="192.168.1.100"/>',
        '<api_key>AIzaSyD4W9x8K3mN7pQ2rT5vY8wZ1aB3cD4eF5g</api_key>',
        '<password>password</password>',  # Should be filtered as placeholder
        '<test_password>test123</test_password>',
    ]

    for i, line in enumerate(test_lines, 1):
        print(f"Line {i}: {line}")
        secrets = list(plugin.analyze_line(
            filename="test.xml",
            line=line,
            line_number=i
        ))
        if secrets:
            for secret in secrets:
                print(f"  ✓ Found secret: {secret.secret_value if hasattr(secret, 'secret_value') else '***'}")
                print(f"     Type: {secret.type}")
        else:
            print(f"  ✗ No secret detected")
        print()

def test_unix_crypt_plugin():
    """Test UnixCryptPlugin"""
    print("\n=== Testing UnixCryptPlugin ===\n")

    plugin = UnixCryptPlugin()

    test_lines = [
        # Real SHA-512 hash (86 char hash)
        '<hash>$6$rounds=5000$saltsalt$5B8vYYiY.CVt1RlTTf11JbZHhjAv123456789012345678901234567890123456789012345678901234567890</hash>',
        # Real MD5 hash (22 char hash)
        '<hash>$1$saltsalt$FooBarBazQuxQuux12</hash>',
        # Real bcrypt hash (53 char salt+hash)
        '<user password="$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"/>',
        # Not a hash
        '<password>normalpassword</password>',
    ]

    for i, line in enumerate(test_lines, 1):
        print(f"Line {i}: {line[:80]}...")
        secrets = list(plugin.analyze_line(
            filename="test.xml",
            line=line,
            line_number=i
        ))
        if secrets:
            for secret in secrets:
                secret_val = secret.secret_value if hasattr(secret, 'secret_value') else '***'
                print(f"  ✓ Found crypt hash: {secret_val[:50] if len(secret_val) > 50 else secret_val}")
                print(f"     Type: {secret.type}")
        else:
            print(f"  ✗ No crypt hash detected")
        print()

def test_xml_plugin_with_filters():
    """Test XMLPasswordPlugin with include/exclude filters"""
    print("\n=== Testing XMLPasswordPlugin with Filters ===\n")

    # Test with include entities filter
    plugin = XMLPasswordPlugin(
        include_entities=['prod_.*', 'production_.*'],
        exclude_entities=['test_.*', 'dev_.*']
    )

    test_lines = [
        '<prod_password>SecretProdPass</prod_password>',  # Should match
        '<test_password>TestPass123</test_password>',      # Should NOT match (excluded)
        '<dev_password>DevPass456</dev_password>',         # Should NOT match (excluded)
        '<production_secret>ProdSecret</production_secret>',  # Should match
    ]

    for i, line in enumerate(test_lines, 1):
        print(f"Line {i}: {line}")
        secrets = list(plugin.analyze_line(
            filename="test.xml",
            line=line,
            line_number=i
        ))
        if secrets:
            for secret in secrets:
                secret_val = secret.secret_value if hasattr(secret, 'secret_value') else '***'
                print(f"  ✓ Found secret: {secret_val}")
                print(f"     Type: {secret.type}")
        else:
            print(f"  ✗ Filtered out (as expected)")
        print()

if __name__ == '__main__':
    test_xml_password_plugin()
    test_unix_crypt_plugin()
    test_xml_plugin_with_filters()
    print("\n=== All Tests Complete ===")
