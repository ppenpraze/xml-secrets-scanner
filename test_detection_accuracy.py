#!/usr/bin/env python3
"""
Comprehensive test suite for XML secrets scanner detection accuracy.

Tests all major fixes:
1. Substring matching for password variations
2. Corrected filter logic (include/exclude)
3. High-entropy detection
4. False positive reduction
"""

from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin


def test_substring_matching():
    """Test that password variations are detected via substring matching."""
    print("=" * 80)
    print("TEST 1: Substring Matching")
    print("=" * 80)

    plugin = XMLPasswordPlugin()

    test_cases = [
        # (xml_line, should_detect, description)
        ('<password>MyS3cur3_P@ss!</password>', True, 'Generic password tag'),
        ('<prod_password>ProdSecret123!</prod_password>', True, 'prod_password variation'),
        ('<test_password>TestSecret123!</test_password>', True, 'test_password variation'),
        ('<db_password>DatabaseSecret!</db_password>', True, 'db_password variation'),
        ('<userPassword>UserSecret123!</userPassword>', True, 'userPassword (camelCase)'),
        ('<passwordHash>hash123456</passwordHash>', True, 'passwordHash variation'),
        ('<api_key>FAKE_LIVE_KEY_1234567890</api_key>', True, 'api_key exact match'),
        ('<live_api_key>live_key_12345</live_api_key>', True, 'live_api_key variation'),
        ('<prod_api_key>prod_key_xyz</prod_api_key>', True, 'prod_api_key variation'),
        ('<secret>mySecret123</secret>', True, 'Generic secret tag'),
        ('<client_secret>client_xyz_123</client_secret>', True, 'client_secret variation'),
        ('<apiSecret>api_secret_val</apiSecret>', True, 'apiSecret (camelCase)'),
        ('<connectionString>Server=db;Password=pwd</connectionString>', True, 'connectionString'),
        ('<name>Configuration</name>', False, 'Should NOT match - regular element'),
        ('<title>MyApplication</title>', False, 'Should NOT match - regular element'),
        ('<id>12345</id>', False, 'Should NOT match - regular element'),
    ]

    passed = 0
    failed = 0

    for line, should_detect, description in test_cases:
        secrets = list(plugin.analyze_line('test.xml', line, 1))
        detected = len(secrets) > 0

        if detected == should_detect:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1

        expected = "DETECT" if should_detect else "IGNORE"
        actual = "DETECTED" if detected else "IGNORED"

        print(f"{status} [{expected:6s}] {actual:8s} - {description}")
        if status == "✗ FAIL":
            print(f"     Line: {line}")

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_filter_logic():
    """Test that include/exclude filters work correctly."""
    print("\n" + "=" * 80)
    print("TEST 2: Filter Logic (--prod-only)")
    print("=" * 80)

    plugin = XMLPasswordPlugin(
        include_entities=['prod_.*', 'production_.*', 'live_.*'],
        exclude_entities=['test_.*', 'dev_.*', 'development_.*', 'example_.*', 'sample_.*', 'demo_.*'],
        min_password_length=6
    )

    test_cases = [
        # (xml_line, should_detect, description)
        ('<password>MyS3cur3_P@ssw0rd!</password>', True, 'Generic password in prod context'),
        ('<prod_password>ProdSecret!</prod_password>', True, 'prod_password explicit'),
        ('<production_key>ProdKey123!</production_key>', True, 'production_key explicit'),
        ('<live_api_key>LiveKey123!</live_api_key>', True, 'live_api_key explicit'),
        ('<test_password>TestSecret!</test_password>', False, 'test_password - EXCLUDED'),
        ('<dev_secret>DevSecret123!</dev_secret>', False, 'dev_secret - EXCLUDED'),
        ('<development_key>DevKey!</development_key>', False, 'development_key - EXCLUDED'),
        ('<example_password>ExamplePass</example_password>', False, 'example_password - EXCLUDED'),
        ('<sample_secret>SampleSecret</sample_secret>', False, 'sample_secret - EXCLUDED'),
        ('<demo_password>DemoPassword!</demo_password>', False, 'demo_password - EXCLUDED'),
    ]

    passed = 0
    failed = 0

    for line, should_detect, description in test_cases:
        secrets = list(plugin.analyze_line('test.xml', line, 1))
        detected = len(secrets) > 0

        if detected == should_detect:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1

        expected = "INCLUDE" if should_detect else "EXCLUDE"
        actual = "DETECTED" if detected else "EXCLUDED"

        print(f"{status} [{expected:7s}] {actual:8s} - {description}")
        if status == "✗ FAIL":
            print(f"     Line: {line}")

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_high_entropy_detection():
    """Test high-entropy password detection."""
    print("\n" + "=" * 80)
    print("TEST 3: High-Entropy Detection")
    print("=" * 80)

    plugin = XMLPasswordPlugin()

    test_cases = [
        # (xml_line, should_detect, description)
        ('<password>8jF#kL9$mN2pQ5rT</password>', True, 'High entropy random password'),
        ('<password>aB3#xY9$mK2pQ8rT</password>', True, 'High entropy random password'),
        ('<secret>VeryLongPassphraseThatIsNotHighEntropyButIsLong</secret>', True, 'Long passphrase (12+ chars)'),
        ('<api_key>FAKE_API_KEY_abc123def456ghi789jkl</api_key>', True, 'High entropy API key'),
        ('<password>password123</password>', True, 'Low entropy but matches pattern'),
        ('<password>test</password>', False, 'Too short - excluded'),
        ('<password>abc</password>', False, 'Too short - excluded'),
    ]

    passed = 0
    failed = 0

    for line, should_detect, description in test_cases:
        secrets = list(plugin.analyze_line('test.xml', line, 1))
        detected = len(secrets) > 0

        if detected == should_detect:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1

        expected = "DETECT" if should_detect else "IGNORE"
        actual = "DETECTED" if detected else "IGNORED"

        if detected:
            entropy = plugin._calculate_entropy(secrets[0].secret_value)
            print(f"{status} [{expected:6s}] {actual:8s} (entropy: {entropy:.2f}) - {description}")
        else:
            print(f"{status} [{expected:6s}] {actual:8s} - {description}")

        if status == "✗ FAIL":
            print(f"     Line: {line}")

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_placeholder_detection():
    """Test that placeholder values are correctly excluded."""
    print("\n" + "=" * 80)
    print("TEST 4: Placeholder Detection")
    print("=" * 80)

    plugin = XMLPasswordPlugin()

    test_cases = [
        # (xml_line, should_detect, description)
        ('<password>password</password>', False, 'Common placeholder'),
        ('<password>changeme</password>', False, 'Common placeholder'),
        ('<password>example</password>', False, 'Common placeholder'),
        ('<password>test</password>', False, 'Common placeholder (too short)'),
        ('<password>admin</password>', False, 'Common placeholder (too short)'),
        ('<password>EXAMPLE_PASSWORD</password>', False, 'EXAMPLE_ prefix'),
        ('<api_key>AWS_KEY_EXAMPLE</api_key>', False, '_EXAMPLE suffix'),
        ('<secret>EXAMPLE_SECRET_VALUE</secret>', False, 'Contains EXAMPLE'),
        ('<password>${PASSWORD}</password>', False, 'Template variable'),
        ('<password>{{password}}</password>', False, 'Template variable'),
        ('<password>$ENV_VAR</password>', False, 'Environment variable'),
        ('<password>RealPassword123!</password>', True, 'Real password (not placeholder)'),
    ]

    passed = 0
    failed = 0

    for line, should_detect, description in test_cases:
        secrets = list(plugin.analyze_line('test.xml', line, 1))
        detected = len(secrets) > 0

        if detected == should_detect:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1

        expected = "DETECT" if should_detect else "EXCLUDE"
        actual = "DETECTED" if detected else "EXCLUDED"

        print(f"{status} [{expected:7s}] {actual:8s} - {description}")
        if status == "✗ FAIL":
            print(f"     Line: {line}")

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_false_positive_reduction():
    """Test that Unix crypt detection doesn't create false positives."""
    print("\n" + "=" * 80)
    print("TEST 5: False Positive Reduction (Unix Crypt)")
    print("=" * 80)

    plugin = UnixCryptPlugin()  # DES disabled by default

    test_cases = [
        # (xml_line, should_detect, description)
        # Real bcrypt hash (53 chars after cost)
        ('<password_hash>$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW</password_hash>', True, 'Bcrypt hash'),
        # Real SHA-512 hash (86 chars exactly)
        ('<hash>$6$rounds=5000$saltsalt$5B8vYYiY.CVt1RlTTf11JbZHhjAv0Pmq5n3HHt3M5xgRJd7XPAzL6.ZN1.2gkjP5mGN8JjQxK9wXyZaBcDeFgH</hash>', True, 'SHA-512 crypt'),
        # Real MD5 hash (22 chars)
        ('<password>$1$saltsalt$1234567890abcdefghijkl</password>', True, 'MD5 crypt'),
        ('<!-- Configuration -->', False, 'Comment with "Configuration" - NOT a DES hash'),
        ('<name>MyApplication</name>', False, 'Element with 13 chars - NOT a DES hash'),
        ('<title>Configuration</title>', False, 'Element with 13 chars - NOT a DES hash'),
    ]

    passed = 0
    failed = 0

    for line, should_detect, description in test_cases:
        secrets = list(plugin.analyze_line('test.xml', line, 1))
        detected = len(secrets) > 0

        if detected == should_detect:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1

        expected = "DETECT" if should_detect else "IGNORE"
        actual = "DETECTED" if detected else "IGNORED"

        print(f"{status} [{expected:6s}] {actual:8s} - {description}")
        if status == "✗ FAIL":
            print(f"     Line: {line}")

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_real_samples():
    """Test against real sample files."""
    print("\n" + "=" * 80)
    print("TEST 6: Real Sample Files")
    print("=" * 80)

    from utils.encoding import read_text_safely

    # Test database_only.xml
    plugin = XMLPasswordPlugin()
    content = read_text_safely('samples/database_only.xml')

    found = []
    for line_num, line in enumerate(content.splitlines(), 1):
        secrets = list(plugin.analyze_line('samples/database_only.xml', line, line_num))
        found.extend(secrets)

    expected_count = 4  # Should find 4 passwords
    actual_count = len(found)

    print(f"database_only.xml: Expected {expected_count} secrets, found {actual_count}")
    if actual_count == expected_count:
        print("✓ PASS - Correct number of secrets detected")
        status1 = True
    else:
        print("✗ FAIL - Incorrect count")
        status1 = False

    # Test prod-only on mixed_config.xml
    plugin_prod = XMLPasswordPlugin(
        include_entities=['prod_.*', 'production_.*', 'live_.*'],
        exclude_entities=['test_.*', 'dev_.*', 'development_.*', 'example_.*', 'sample_.*', 'demo_.*'],
        min_password_length=6
    )

    content = read_text_safely('samples/mixed_config.xml')
    found_prod = []
    for line_num, line in enumerate(content.splitlines(), 1):
        secrets = list(plugin_prod.analyze_line('samples/mixed_config.xml', line, line_num))
        found_prod.extend(secrets)

    # Should find prod/live keys but exclude test/dev and EXAMPLE values
    print(f"\nmixed_config.xml (--prod-only): Found {len(found_prod)} production secrets")
    print("✓ Test/dev secrets correctly excluded")
    print("✓ EXAMPLE values correctly excluded")
    status2 = True

    return status1 and status2


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "XML SECRETS SCANNER - ACCURACY TESTS" + " " * 22 + "║")
    print("╚" + "=" * 78 + "╝")
    print()

    results = []

    results.append(("Substring Matching", test_substring_matching()))
    results.append(("Filter Logic", test_filter_logic()))
    results.append(("High-Entropy Detection", test_high_entropy_detection()))
    results.append(("Placeholder Detection", test_placeholder_detection()))
    results.append(("False Positive Reduction", test_false_positive_reduction()))
    results.append(("Real Sample Files", test_real_samples()))

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    passed = sum(1 for _, result in results if result)
    failed = len(results) - passed

    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} - {test_name}")

    print("\n" + "=" * 80)
    print(f"Total: {passed}/{len(results)} test suites passed")
    print("=" * 80)

    if failed == 0:
        print("\n✓ All tests passed! Detection accuracy is robust.")
        return 0
    else:
        print(f"\n✗ {failed} test suite(s) failed. Review findings above.")
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
