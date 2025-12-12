#!/usr/bin/env python3
"""
Scan a directory using detect-secrets plugins (built-in + custom).

This script uses ALL available detect-secrets plugins including:
- Custom XML plugins (XMLPasswordPlugin, UnixCryptPlugin)
- Built-in plugins (AWS, Stripe, Private Keys, etc.)

Usage:
    python3 scan_with_plugins.py <directory> [options]

Examples:
    # Scan with all plugins (default)
    python3 scan_with_plugins.py /path/to/repo

    # Scan production secrets only
    python3 scan_with_plugins.py /path/to/repo --prod-only

    # List available plugins
    python3 scan_with_plugins.py --list-plugins

    # Enable only specific plugins
    python3 scan_with_plugins.py /path/to/repo --only xml_password,aws,private_key

    # Disable specific plugins
    python3 scan_with_plugins.py /path/to/repo --disable stripe,discord
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any
from plugin_manager import PluginManager
from utils.encoding import read_text_safely


def scan_file(file_path: str, plugin_manager: PluginManager) -> List[Dict[str, Any]]:
    """Scan a single file for secrets using all enabled plugins."""
    results = []

    try:
        # Read using robust encoding to avoid UnicodeDecodeError
        content = read_text_safely(file_path)

        for line_num, line in enumerate(content.splitlines(True), 1):
            # Scan with all enabled plugins
            for secret in plugin_manager.scan_line(str(file_path), line, line_num):
                # Only include if secret value exists and is not empty
                secret_value = secret.secret_value if hasattr(secret, 'secret_value') else None

                if secret_value:
                    results.append({
                        'file': str(file_path),
                        'line_number': line_num,
                        'type': secret.type,
                        'secret': secret_value,
                        'line_content': line.strip()
                    })

    except Exception as e:
        print(f"Error scanning {file_path}: {e}", file=sys.stderr)

    return results


def scan_directory(
    directory: str,
    plugin_manager: PluginManager,
    extensions: List[str] = None
) -> List[Dict[str, Any]]:
    """Scan a directory recursively for secrets."""
    if extensions is None:
        extensions = ['.xml', '.config', '.conf', '.properties', '.yaml', '.yml', '.json', '.txt', '.env']

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
    print(f"Enabled plugins: {', '.join(plugin_manager.get_enabled_plugins())}")
    print(f"File extensions: {', '.join(extensions)}")
    print()

    for file_path in path.rglob('*'):
        if file_path.is_file() and file_path.suffix in extensions:
            file_count += 1
            results = scan_file(str(file_path), plugin_manager)
            all_results.extend(results)

            if results:
                print(f"Found {len(results)} secret(s) in: {file_path}")

    print(f"\nScanned {file_count} files with {plugin_manager.get_plugin_count()} plugins")
    return all_results


def list_plugins():
    """List all available plugins."""
    print("Available Plugins:")
    print("=" * 80)

    for plugin_info in PluginManager.list_available_plugins():
        enabled = "✓" if plugin_info['enabled_default'] else " "
        print(f"  [{enabled}] {plugin_info['name']:20s} - {plugin_info['description']}")

    print("\n" + "=" * 80)
    print("✓ = Enabled by default")
    print("\nUse --only or --disable to control which plugins run")


def main():
    parser = argparse.ArgumentParser(
        description='Scan directories for secrets using all detect-secrets plugins',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with all plugins (default)
  %(prog)s /path/to/repo --output results.json

  # Scan production secrets only (XML plugin filtering)
  %(prog)s /path/to/repo --prod-only

  # List available plugins
  %(prog)s --list-plugins

  # Enable only specific plugins
  %(prog)s /path/to/repo --only xml_password,aws,private_key

  # Disable specific plugins
  %(prog)s /path/to/repo --disable stripe,discord,telegram

  # Scan specific file types
  %(prog)s /path/to/repo --extensions .xml .yaml .json
        """
    )

    parser.add_argument('directory', nargs='?', help='Directory to scan')
    parser.add_argument('--output', '-o', help='Output file (JSON format)')
    parser.add_argument('--extensions', '-e', nargs='+',
                       help='File extensions to scan')

    # Plugin control
    parser.add_argument('--list-plugins', action='store_true',
                       help='List all available plugins and exit')
    parser.add_argument('--only',
                       help='Enable only these plugins (comma-separated)')
    parser.add_argument('--disable',
                       help='Disable these plugins (comma-separated)')

    # XML plugin specific options
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
    parser.add_argument('--ignore-values', nargs='+',
                       help='Additional values to ignore as false positives (e.g., "myapp" "config123")')
    parser.add_argument('--prod-only', action='store_true',
                       help='Scan production secrets only (shorthand for common filters)')

    # Unix crypt options
    parser.add_argument('--disable-unix-crypt', action='store_true',
                       help='Disable Unix crypt hash detection')

    args = parser.parse_args()

    # Handle --list-plugins
    if args.list_plugins:
        list_plugins()
        return 0

    # Require directory if not listing plugins
    if not args.directory:
        parser.error("directory is required (unless using --list-plugins)")

    # Parse plugin control options
    enabled_plugins = None
    disabled_plugins = []

    if args.only:
        enabled_plugins = [p.strip() for p in args.only.split(',')]

    if args.disable:
        disabled_plugins = [p.strip() for p in args.disable.split(',')]

    if args.disable_unix_crypt:
        disabled_plugins.append('unix_crypt')

    # Configure XML plugin based on arguments
    xml_password_config = {}

    if args.prod_only:
        xml_password_config = {
            'include_entities': ['prod_.*', 'production_.*', 'live_.*'],
            'exclude_entities': ['test_.*', 'dev_.*', 'development_.*', 'example_.*', 'sample_.*', 'demo_.*'],
            'min_password_length': 6
        }
    else:
        if args.include_entities:
            xml_password_config['include_entities'] = args.include_entities
        if args.exclude_entities:
            xml_password_config['exclude_entities'] = args.exclude_entities
        if args.include_attributes:
            xml_password_config['include_attributes'] = args.include_attributes
        if args.exclude_attributes:
            xml_password_config['exclude_attributes'] = args.exclude_attributes
        xml_password_config['min_password_length'] = args.min_length

    # Add custom ignore values if provided
    if args.ignore_values:
        xml_password_config['ignore_values'] = args.ignore_values

    # Create plugin manager
    plugin_manager = PluginManager(
        enabled_plugins=enabled_plugins,
        disabled_plugins=disabled_plugins,
        xml_password_config=xml_password_config
    )

    # Scan directory
    results = scan_directory(
        args.directory,
        plugin_manager,
        extensions=args.extensions
    )

    # Generate output
    output = {
        'scan_directory': args.directory,
        'enabled_plugins': plugin_manager.get_enabled_plugins(),
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
    print(f"Summary: Found {len(results)} secrets using {plugin_manager.get_plugin_count()} plugins")
    print(f"{'='*80}")

    # Exit with error code if secrets found
    sys.exit(1 if results else 0)


if __name__ == '__main__':
    sys.exit(main())
