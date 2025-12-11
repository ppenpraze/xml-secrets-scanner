#!/usr/bin/env python3
"""
Scan a directory using custom detect-secrets plugins.

This script uses the XMLPasswordPlugin and UnixCryptPlugin to scan
directories for secrets with the actual secret values shown in output.

Usage:
    python3 scan_with_plugins.py <directory> [options]

Examples:
    # Scan with default settings
    python3 scan_with_plugins.py /path/to/repo

    # Scan production secrets only
    python3 scan_with_plugins.py /path/to/repo --prod-only

    # Scan with custom output
    python3 scan_with_plugins.py /path/to/repo --output results.json

    # Scan specific file extensions
    python3 scan_with_plugins.py /path/to/repo --extensions .xml .config
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin


def scan_file(file_path: str, xml_plugin: XMLPasswordPlugin, unix_plugin: UnixCryptPlugin) -> List[Dict[str, Any]]:
    """Scan a single file for secrets."""
    results = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Check with XML password plugin
                for secret in xml_plugin.analyze_line(str(file_path), line, line_num):
                    results.append({
                        'file': str(file_path),
                        'line_number': line_num,
                        'type': secret.type,
                        'secret': secret.secret_value if hasattr(secret, 'secret_value') else '***',
                        'line_content': line.strip()
                    })

                # Check with Unix crypt plugin
                for secret in unix_plugin.analyze_line(str(file_path), line, line_num):
                    results.append({
                        'file': str(file_path),
                        'line_number': line_num,
                        'type': secret.type,
                        'secret': secret.secret_value if hasattr(secret, 'secret_value') else '***',
                        'line_content': line.strip()
                    })
    except Exception as e:
        print(f"Error scanning {file_path}: {e}", file=sys.stderr)

    return results


def scan_directory(
    directory: str,
    xml_plugin: XMLPasswordPlugin,
    unix_plugin: UnixCryptPlugin,
    extensions: List[str] = None
) -> List[Dict[str, Any]]:
    """Scan a directory recursively for secrets."""
    if extensions is None:
        extensions = ['.xml', '.config', '.conf', '.properties', '.yaml', '.yml']

    path = Path(directory)
    if not path.exists():
        print(f"Error: Directory does not exist: {directory}", file=sys.stderr)
        sys.exit(1)

    if not path.is_dir():
        print(f"Error: Path is not a directory: {directory}", file=sys.stderr)
        sys.exit(1)

    all_results = []
    file_count = 0

    print(f"Scanning directory: {directory}")
    print(f"File extensions: {', '.join(extensions)}")
    print()

    for file_path in path.rglob('*'):
        if file_path.is_file() and file_path.suffix in extensions:
            file_count += 1
            results = scan_file(str(file_path), xml_plugin, unix_plugin)
            all_results.extend(results)

            if results:
                print(f"Found {len(results)} secret(s) in: {file_path}")

    print(f"\nScanned {file_count} files")
    return all_results


def main():
    parser = argparse.ArgumentParser(
        description='Scan directories for secrets using custom detect-secrets plugins',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with default settings
  %(prog)s /path/to/repo

  # Scan production secrets only
  %(prog)s /path/to/repo --prod-only

  # Scan with custom filters
  %(prog)s /path/to/repo --include-entities "prod_.*" "live_.*" --exclude-entities "test_.*"

  # Save output to JSON
  %(prog)s /path/to/repo --output results.json

  # Scan specific extensions
  %(prog)s /path/to/repo --extensions .xml .yaml .properties
        """
    )

    parser.add_argument('directory', help='Directory to scan')
    parser.add_argument('--output', '-o', help='Output file (JSON format)')
    parser.add_argument('--extensions', '-e', nargs='+',
                       help='File extensions to scan (default: .xml .config .conf .properties .yaml .yml)')
    parser.add_argument('--include-entities', nargs='+',
                       help='Include only these entity patterns (regex)')
    parser.add_argument('--exclude-entities', nargs='+',
                       help='Exclude these entity patterns (regex)')
    parser.add_argument('--include-attributes', nargs='+',
                       help='Include only these attribute patterns (regex)')
    parser.add_argument('--exclude-attributes', nargs='+',
                       help='Exclude these attribute patterns (regex)')
    parser.add_argument('--min-length', type=int, default=4,
                       help='Minimum password length (default: 4)')
    parser.add_argument('--prod-only', action='store_true',
                       help='Scan production secrets only (shorthand for common filters)')
    parser.add_argument('--disable-unix-crypt', action='store_true',
                       help='Disable Unix crypt hash detection')

    args = parser.parse_args()

    # Configure plugins based on arguments
    if args.prod_only:
        # Production-only shorthand
        xml_plugin = XMLPasswordPlugin(
            include_entities=['prod_.*', 'production_.*', 'live_.*'],
            exclude_entities=['test_.*', 'dev_.*', 'development_.*', 'example_.*', 'sample_.*', 'demo_.*'],
            min_password_length=6
        )
    else:
        # Use custom or default settings
        xml_plugin = XMLPasswordPlugin(
            include_entities=args.include_entities,
            exclude_entities=args.exclude_entities,
            include_attributes=args.include_attributes,
            exclude_attributes=args.exclude_attributes,
            min_password_length=args.min_length
        )

    unix_plugin = UnixCryptPlugin() if not args.disable_unix_crypt else None

    # Scan directory
    results = scan_directory(
        args.directory,
        xml_plugin,
        unix_plugin,
        extensions=args.extensions
    )

    # Generate output
    output = {
        'scan_directory': args.directory,
        'total_secrets_found': len(results),
        'secrets': results
    }

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\nResults written to: {args.output}")
    else:
        print("\n" + "="*80)
        print("RESULTS")
        print("="*80)
        print(json.dumps(output, indent=2))

    # Summary
    print(f"\n{'='*80}")
    print(f"Summary: Found {len(results)} secrets")
    print(f"{'='*80}")

    # Exit with error code if secrets found
    sys.exit(1 if results else 0)


if __name__ == '__main__':
    main()
