#!/usr/bin/env python3
"""
Test ignore values functionality - verify that common false positives are excluded.
"""

from xml_plugins import XMLPasswordPlugin


def test_default_ignore_values():
    """Test that default ignore values (true, false, null, etc.) are excluded."""
    print("=" * 80)
    print("TEST: Default Ignore Values")
    print("=" * 80)

    plugin = XMLPasswordPlugin()

    test_cases = [
        # (xml_line, should_detect, description)
        ('<password>true</password>', False, 'Boolean "true" should be ignored'),
        ('<password>false</password>', False, 'Boolean "false" should be ignored'),
        ('<password>True</password>', False, 'Boolean "True" (capitalized) should be ignored'),
        ('<password>FALSE</password>', False, 'Boolean "FALSE" (uppercase) should be ignored'),
        ('<password>null</password>', False, 'Null value should be ignored'),
        ('<password>None</password>', False, 'None value should be ignored'),
        ('<password>nil</password>', False, 'Nil value should be ignored'),
        ('<password>undefined</password>', False, 'Undefined value should be ignored'),
        ('<password>yes</password>', False, 'Config value "yes" should be ignored'),
        ('<password>no</password>', False, 'Config value "no" should be ignored'),
        ('<password>on</password>', False, 'Config value "on" should be ignored'),
        ('<password>off</password>', False, 'Config value "off" should be ignored'),
        ('<password>enabled</password>', False, 'Config value "enabled" should be ignored'),
        ('<password>disabled</password>', False, 'Config value "disabled" should be ignored'),
        ('<password>default</password>', False, 'Config value "default" should be ignored'),
        ('<password>empty</password>', False, 'Config value "empty" should be ignored'),
        ('<password>blank</password>', False, 'Config value "blank" should be ignored'),
        ('<password>x</password>', False, 'Single character "x" should be ignored'),
        ('<password>1</password>', False, 'Single digit "1" should be ignored'),
        ('<password>0</password>', False, 'Single digit "0" should be ignored'),
        ('<password>RealPassword123!</password>', True, 'Real password should be detected'),
        ('<api_key>REAL_API_KEY_abc123</api_key>', True, 'Real API key should be detected'),
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


def test_custom_ignore_values():
    """Test that custom ignore values can be provided."""
    print("\n" + "=" * 80)
    print("TEST: Custom Ignore Values")
    print("=" * 80)

    # Create plugin with custom ignore values
    plugin = XMLPasswordPlugin(
        ignore_values=['myapp', 'config123', 'localhost']
    )

    test_cases = [
        # (xml_line, should_detect, description)
        ('<password>myapp</password>', False, 'Custom ignore "myapp" should be ignored'),
        ('<password>MyApp</password>', False, 'Custom ignore "MyApp" (case-insensitive) should be ignored'),
        ('<password>config123</password>', False, 'Custom ignore "config123" should be ignored'),
        ('<password>localhost</password>', False, 'Custom ignore "localhost" should be ignored'),
        ('<password>true</password>', False, 'Default ignore "true" still works'),
        ('<password>false</password>', False, 'Default ignore "false" still works'),
        ('<password>RealPassword123!</password>', True, 'Real password should be detected'),
        ('<password>differentapp</password>', True, 'Non-ignored value should be detected'),
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


def test_xml_attributes():
    """Test that ignore values work for XML attributes too."""
    print("\n" + "=" * 80)
    print("TEST: Ignore Values in XML Attributes")
    print("=" * 80)

    plugin = XMLPasswordPlugin(
        ignore_values=['myapp']
    )

    test_cases = [
        # (xml_line, should_detect, description)
        ('password="true"', False, 'Attribute with "true" should be ignored'),
        ('password="false"', False, 'Attribute with "false" should be ignored'),
        ('password="null"', False, 'Attribute with "null" should be ignored'),
        ('password="myapp"', False, 'Attribute with custom ignore "myapp" should be ignored'),
        ('password="RealPassword123"', True, 'Attribute with real password should be detected'),
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


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 25 + "IGNORE VALUES TESTS" + " " * 34 + "║")
    print("╚" + "=" * 78 + "╝")
    print()

    results = [
        ("Default Ignore Values", test_default_ignore_values()),
        ("Custom Ignore Values", test_custom_ignore_values()),
        ("Ignore Values in Attributes", test_xml_attributes()),
    ]

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
        print("\n✓ All tests passed! Ignore values work correctly.")
        return 0
    else:
        print(f"\n✗ {failed} test suite(s) failed. Review findings above.")
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
