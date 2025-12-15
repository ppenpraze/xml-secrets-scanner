#!/usr/bin/env python3
"""
Test that WEAK PASSWORDS are DETECTED, not filtered.

CRITICAL: Weak passwords like 'password', 'admin', '123456' are REAL security risks
that MUST be flagged, even though they're common. They should NOT be filtered as placeholders.
"""

from xml_plugins import XMLPasswordPlugin

def test_weak_passwords_are_detected():
    """Verify that common weak passwords ARE detected as security risks."""
    print("=" * 80)
    print("TEST: Weak Password Detection (MUST detect, not filter)")
    print("=" * 80)
    print()

    plugin = XMLPasswordPlugin()

    # These are REAL weak passwords that MUST be detected
    weak_password_cases = [
        # Common weak passwords
        ('<password>password</password>', True, 'Weak: "password" - MUST DETECT'),
        ('<password>Password</password>', True, 'Weak: "Password" - MUST DETECT'),
        ('<password>PASSWORD</password>', True, 'Weak: "PASSWORD" - MUST DETECT'),
        ('<password>changeme</password>', True, 'Weak: "changeme" - MUST DETECT'),
        ('<password>admin</password>', True, 'Weak: "admin" - MUST DETECT'),
        ('<password>Admin</password>', True, 'Weak: "Admin" - MUST DETECT'),

        # Common numeric weak passwords
        ('<password>123456</password>', True, 'Weak: "123456" - MUST DETECT'),
        ('<password>12345678</password>', True, 'Weak: "12345678" - MUST DETECT'),
        ('<password>1234567890</password>', True, 'Weak: "1234567890" - MUST DETECT'),

        # Common keyboard patterns
        ('<password>qwerty</password>', True, 'Weak: "qwerty" - MUST DETECT'),
        ('<password>letmein</password>', True, 'Weak: "letmein" - MUST DETECT'),

        # Default credentials
        ('<password>root</password>', True, 'Weak: "root" - MUST DETECT'),
        ('<password>guest</password>', True, 'Weak: "guest" - MUST DETECT'),

        # Still filter ONLY documentation placeholders
        ('<password>placeholder</password>', False, 'Documentation placeholder - OK to filter'),
        ('<password>example</password>', False, 'Documentation placeholder - OK to filter'),
        ('<password>xxx</password>', False, 'Documentation placeholder - OK to filter'),
        ('<password>****</password>', False, 'Redaction marker - OK to filter'),
        ('<password>your_password_here</password>', False, 'Instruction text - OK to filter'),

        # Filter boolean/config values
        ('<password>true</password>', False, 'Boolean - OK to filter'),
        ('<password>enabled</password>', False, 'Config value - OK to filter'),
    ]

    passed = 0
    failed = 0
    critical_failures = []

    for line, should_detect, description in weak_password_cases:
        secrets = list(plugin.analyze_line('test.xml', line, 1))
        detected = len(secrets) > 0

        if detected == should_detect:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1
            if should_detect:  # This is a critical failure - weak password not detected!
                critical_failures.append((line, description))

        expected = "DETECT" if should_detect else "FILTER"
        actual = "DETECTED" if detected else "FILTERED"

        print(f"{status} [{expected:6s}] {actual:8s} - {description}")
        if status == "✗ FAIL":
            print(f"     Line: {line}")

    print()
    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed")

    if critical_failures:
        print()
        print("⚠️  CRITICAL FAILURES (weak passwords not detected):")
        for line, desc in critical_failures:
            print(f"  ✗ {desc}")
            print(f"    {line}")
        print()
        print("These are REAL security risks that MUST be detected!")

    print("=" * 80)

    return failed == 0


if __name__ == '__main__':
    import sys
    success = test_weak_passwords_are_detected()
    sys.exit(0 if success else 1)
