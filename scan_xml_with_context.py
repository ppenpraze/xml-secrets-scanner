#!/usr/bin/env python3
"""
XML Secret Scanner with Context

Enhanced scanner that:
1. Normalizes XML files first
2. Parses XML structure to capture parent elements
3. Includes parent element path in output
4. Provides better context for secret detection
"""

import argparse
import json
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin
from normalize_xml import normalize_xml_content


def get_element_path(element, root) -> str:
    """
    Get the XPath-like path to an element.

    Args:
        element: The XML element
        root: The root element

    Returns:
        Path like "/configuration/database/password"
    """
    path_parts = []
    current = element

    # Walk up the tree
    while current is not None:
        # Find parent
        parent = None
        for elem in root.iter():
            for child in elem:
                if child == current:
                    parent = elem
                    break
            if parent is not None:
                break

        path_parts.insert(0, current.tag)
        current = parent

    return "/" + "/".join(path_parts)


def scan_xml_element(element, parent_path: str, xml_plugin: XMLPasswordPlugin,
                     unix_plugin: UnixCryptPlugin, filename: str) -> List[Dict[str, Any]]:
    """
    Scan an XML element and its children for secrets.

    Args:
        element: XML element to scan
        parent_path: Path to parent element
        xml_plugin: XMLPasswordPlugin instance
        unix_plugin: UnixCryptPlugin instance
        filename: Source filename

    Returns:
        List of detected secrets with context
    """
    results = []
    current_path = f"{parent_path}/{element.tag}" if parent_path else f"/{element.tag}"

    # Check element text (value)
    if element.text and element.text.strip():
        text = element.text.strip()
        line_content = f"<{element.tag}>{text}</{element.tag}>"

        # Check with XML password plugin
        for secret in xml_plugin.analyze_line(filename, line_content, 0):
            results.append({
                'file': filename,
                'element_path': current_path,
                'parent_element': element.tag,
                'type': secret.type,
                'secret': secret.secret_value if hasattr(secret, 'secret_value') else '***',
                'line_content': line_content,
                'detection_method': 'element_value'
            })

        # Check with Unix crypt plugin
        for secret in unix_plugin.analyze_line(filename, line_content, 0):
            results.append({
                'file': filename,
                'element_path': current_path,
                'parent_element': element.tag,
                'type': secret.type,
                'secret': secret.secret_value if hasattr(secret, 'secret_value') else '***',
                'line_content': line_content,
                'detection_method': 'element_value'
            })

    # Check attributes
    for attr_name, attr_value in element.attrib.items():
        if attr_value:
            line_content = f'{attr_name}="{attr_value}"'

            # Check with XML password plugin
            for secret in xml_plugin.analyze_line(filename, line_content, 0):
                results.append({
                    'file': filename,
                    'element_path': current_path,
                    'parent_element': element.tag,
                    'attribute_name': attr_name,
                    'type': secret.type,
                    'secret': secret.secret_value if hasattr(secret, 'secret_value') else '***',
                    'line_content': line_content,
                    'detection_method': 'attribute'
                })

            # Check with Unix crypt plugin
            for secret in unix_plugin.analyze_line(filename, line_content, 0):
                results.append({
                    'file': filename,
                    'element_path': current_path,
                    'parent_element': element.tag,
                    'attribute_name': attr_name,
                    'type': secret.type,
                    'secret': secret.secret_value if hasattr(secret, 'secret_value') else '***',
                    'line_content': line_content,
                    'detection_method': 'attribute'
                })

    # Recursively scan children
    for child in element:
        results.extend(scan_xml_element(child, current_path, xml_plugin, unix_plugin, filename))

    return results


def scan_xml_file(file_path: str, xml_plugin: XMLPasswordPlugin,
                  unix_plugin: UnixCryptPlugin, normalize: bool = True) -> List[Dict[str, Any]]:
    """
    Scan an XML file for secrets with full context.

    Args:
        file_path: Path to XML file
        xml_plugin: XMLPasswordPlugin instance
        unix_plugin: UnixCryptPlugin instance
        normalize: Whether to normalize XML first

    Returns:
        List of detected secrets with context
    """
    try:
        # Read XML content
        with open(file_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()

        # Normalize if requested
        if normalize:
            xml_content = normalize_xml_content(xml_content)

        # Parse XML
        root = ET.fromstring(xml_content)

        # Scan the XML tree
        results = scan_xml_element(root, "", xml_plugin, unix_plugin, file_path)

        return results

    except ET.ParseError as e:
        print(f"Error parsing {file_path}: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error scanning {file_path}: {e}", file=sys.stderr)
        return []


def scan_directory(directory: str, xml_plugin: XMLPasswordPlugin,
                   unix_plugin: UnixCryptPlugin, extensions: List[str] = None,
                   normalize: bool = True) -> List[Dict[str, Any]]:
    """
    Scan a directory for secrets in XML files.

    Args:
        directory: Directory path
        xml_plugin: XMLPasswordPlugin instance
        unix_plugin: UnixCryptPlugin instance
        extensions: File extensions to scan
        normalize: Whether to normalize XML first

    Returns:
        List of all detected secrets
    """
    if extensions is None:
        extensions = ['.xml', '.config']

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
    print(f"Normalization: {'enabled' if normalize else 'disabled'}")
    print(f"File extensions: {', '.join(extensions)}")
    print()

    for file_path in path.rglob('*'):
        if file_path.is_file() and file_path.suffix in extensions:
            file_count += 1
            results = scan_xml_file(str(file_path), xml_plugin, unix_plugin, normalize)
            all_results.extend(results)

            if results:
                print(f"Found {len(results)} secret(s) in: {file_path}")

    print(f"\nScanned {file_count} files")
    return all_results


def main():
    parser = argparse.ArgumentParser(
        description='Scan XML files for secrets with full context (includes parent elements)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with normalization (handles multi-line XML)
  %(prog)s /path/to/repo --output results.json

  # Production secrets only
  %(prog)s /path/to/repo --prod-only --output prod.json

  # Without normalization (faster, but may miss multi-line values)
  %(prog)s /path/to/repo --no-normalize --output results.json

  # Custom filtering
  %(prog)s /path/to/repo \
    --include-entities "database_.*" "api_.*" \
    --exclude-entities "test_.*" \
    --output results.json
        """
    )

    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('--output', '-o', help='Output file (JSON format)')
    parser.add_argument('--extensions', '-e', nargs='+',
                       help='File extensions to scan (default: .xml .config)')
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
                       help='Scan production secrets only')
    parser.add_argument('--no-normalize', action='store_true',
                       help='Skip XML normalization (faster but may miss multi-line)')
    parser.add_argument('--disable-unix-crypt', action='store_true',
                       help='Disable Unix crypt hash detection')

    args = parser.parse_args()

    # Configure plugins
    if args.prod_only:
        xml_plugin = XMLPasswordPlugin(
            include_entities=['prod_.*', 'production_.*', 'live_.*'],
            exclude_entities=['test_.*', 'dev_.*', 'development_.*', 'example_.*', 'sample_.*', 'demo_.*'],
            min_password_length=6
        )
    else:
        xml_plugin = XMLPasswordPlugin(
            include_entities=args.include_entities,
            exclude_entities=args.exclude_entities,
            include_attributes=args.include_attributes,
            exclude_attributes=args.exclude_attributes,
            min_password_length=args.min_length
        )

    unix_plugin = UnixCryptPlugin() if not args.disable_unix_crypt else None

    # Check if path is file or directory
    input_path = Path(args.path)
    if input_path.is_file():
        # Scan single file
        print(f"Scanning file: {args.path}")
        print(f"Normalization: {'enabled' if not args.no_normalize else 'disabled'}")
        print()
        results = scan_xml_file(str(input_path), xml_plugin, unix_plugin, normalize=not args.no_normalize)
        print(f"Found {len(results)} secret(s)")
    else:
        # Scan directory
        results = scan_directory(
            args.path,
            xml_plugin,
            unix_plugin,
            extensions=args.extensions,
            normalize=not args.no_normalize
        )

    # Generate output
    output = {
        'scan_path': args.path,
        'normalization_enabled': not args.no_normalize,
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
