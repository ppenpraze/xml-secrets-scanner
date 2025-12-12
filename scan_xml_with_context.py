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
from plugin_manager import PluginManager
from utils.encoding import read_text_safely
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


def scan_xml_element(element, parent_path: str, plugin_manager: PluginManager,
                     filename: str) -> List[Dict[str, Any]]:
    """
    Scan an XML element and its children for secrets.

    Args:
        element: XML element to scan
        parent_path: Path to parent element
        plugin_manager: PluginManager instance
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

        # Scan with all enabled plugins
        for secret in plugin_manager.scan_line(filename, line_content, 0):
            # Only include if secret value exists and is not empty
            secret_value = secret.secret_value if hasattr(secret, 'secret_value') else None

            if secret_value:
                results.append({
                    'file': filename,
                    'element_path': current_path,
                    'parent_element': element.tag,
                    'type': secret.type,
                    'secret': secret_value,
                    'line_content': line_content,
                    'detection_method': 'element_value'
                })

    # Check attributes
    for attr_name, attr_value in element.attrib.items():
        if attr_value:
            line_content = f'{attr_name}="{attr_value}"'

            # Scan with all enabled plugins
            for secret in plugin_manager.scan_line(filename, line_content, 0):
                # Only include if secret value exists and is not empty
                secret_value = secret.secret_value if hasattr(secret, 'secret_value') else None

                if secret_value:
                    results.append({
                        'file': filename,
                        'element_path': current_path,
                        'parent_element': element.tag,
                        'attribute_name': attr_name,
                        'type': secret.type,
                        'secret': secret_value,
                        'line_content': line_content,
                        'detection_method': 'attribute'
                    })

    # Recursively scan children
    for child in element:
        results.extend(scan_xml_element(child, current_path, plugin_manager, filename))

    return results


def scan_original_xml(file_path: str, plugin_manager: PluginManager) -> List[Dict[str, Any]]:
    """
    Line-based scan of original XML file (before normalization).

    This captures line numbers from the original file.

    Args:
        file_path: Path to XML file
        plugin_manager: PluginManager instance

    Returns:
        List of detected secrets with original line numbers
    """
    results = []

    try:
        content = read_text_safely(file_path)

        for line_num, line in enumerate(content.splitlines(), 1):
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
                        'line_content': line.strip(),
                        'detection_method': 'original_scan'
                    })

    except Exception as e:
        print(f"Error in original scan of {file_path}: {e}", file=sys.stderr)

    return results


def scan_xml_file(file_path: str, plugin_manager: PluginManager,
                  normalize: bool = True, ns_recovery: bool = True) -> List[Dict[str, Any]]:
    """
    Scan an XML file for secrets with full context using DUAL SCAN approach.

    This function performs TWO scans:
    1. Original scan: Line-based on original file (captures line numbers)
    2. Normalized scan: XML-parsed on normalized file (captures element paths, multi-line secrets)

    Results are merged and deduplicated.

    Args:
        file_path: Path to XML file
        plugin_manager: PluginManager instance
        normalize: Whether to normalize XML first

    Returns:
        List of detected secrets with both line numbers and element context
    """
    def _line_fallback(raw_text: str) -> List[Dict[str, Any]]:
        # Perform a line-based scan so we still catch visible secrets
        results_fb: List[Dict[str, Any]] = []
        for ln, line in enumerate(raw_text.splitlines(True), 1):
            for secret in plugin_manager.scan_line(str(file_path), line, ln):
                # Only include if secret value exists and is not empty
                secret_value = secret.secret_value if hasattr(secret, 'secret_value') else None

                if secret_value:
                    results_fb.append({
                        'file': str(file_path),
                        'line_number': ln,
                        'type': secret.type,
                        'secret': secret_value,
                        'line_content': line.rstrip('\n'),
                        'detection_method': 'line_fallback'
                    })
        return results_fb

    def _sanitize_unbound_prefixes(text: str) -> str:
        """Remove unknown XML namespace prefixes to avoid ET 'unbound prefix' errors.

        This is a best-effort sanitizer: it strips 'prefix:' from element and attribute
        names, e.g., '<a:Tag xlink:href="...">' -> '<Tag href="...">'.
        """
        import re as _re
        # Strip prefixes in element tags
        s = _re.sub(r'<(/?)([A-Za-z_][\w\.-]*):', r'<\1', text)
        # Strip prefixes in attributes: ' prefix:name=' -> ' name='
        s = _re.sub(r'([\s<])([A-Za-z_][\w\.-]*):([A-Za-z_][\w\.-]*)=', r'\1\3=', s)
        return s

    def _find_secret_line_in_original(secret_value: str, original_content: str,
                                       element_tag: str = None) -> Optional[int]:
        """
        Search for a secret in the original file and return its line number.

        Args:
            secret_value: The secret to search for
            original_content: Original file content
            element_tag: Optional element tag to help narrow search (e.g., "password")

        Returns:
            Line number where secret appears, or None if not found
        """
        # Normalize the secret value (remove extra whitespace for multi-line secrets)
        search_value = ' '.join(secret_value.split())

        for line_num, line in enumerate(original_content.splitlines(), 1):
            # Normalize line for comparison
            normalized_line = ' '.join(line.split())

            # Check if secret appears in this line
            if search_value in normalized_line:
                return line_num

            # Also check if the secret spans multiple lines starting from this line
            # (for multi-line secrets that were normalized)
            if element_tag and f'<{element_tag}' in line:
                # This might be the start of the element containing the secret
                return line_num

        return None

    def _merge_results(original_results: List[Dict[str, Any]],
                       normalized_results: List[Dict[str, Any]],
                       original_content: str) -> List[Dict[str, Any]]:
        """
        Merge results from original and normalized scans, deduplicating.

        Strategy:
        - Original results have line numbers but may miss multi-line secrets
        - Normalized results have element paths and catch multi-line secrets
        - Merge by matching on (file, secret, type)
        - Prefer original results (they have line numbers)
        - Add normalized results that weren't found in original
        - For normalized-only results, try to find line number by searching original

        Args:
            original_results: Results from original scan
            normalized_results: Results from normalized scan
            original_content: Original file content (for line lookup)

        Returns:
            Merged and deduplicated results
        """
        merged = []
        seen_secrets = {}  # Key: (file, secret, type) -> result with best info

        # First pass: Add all original results (they have line numbers)
        for result in original_results:
            key = (result['file'], result['secret'], result['type'])
            seen_secrets[key] = result
            merged.append(result)

        # Second pass: Add normalized results, enriching or adding new ones
        for norm_result in normalized_results:
            key = (norm_result['file'], norm_result['secret'], norm_result['type'])

            if key in seen_secrets:
                # Secret was found in original scan - enrich with element path
                orig_result = seen_secrets[key]
                if 'element_path' in norm_result and 'element_path' not in orig_result:
                    orig_result['element_path'] = norm_result['element_path']
                if 'parent_element' in norm_result and 'parent_element' not in orig_result:
                    orig_result['parent_element'] = norm_result['parent_element']
                if 'attribute_name' in norm_result and 'attribute_name' not in orig_result:
                    orig_result['attribute_name'] = norm_result['attribute_name']
                # Mark that it was found in both scans
                orig_result['detection_method'] = 'dual_scan'
            else:
                # New secret found only in normalized scan (multi-line secret)
                # Try to find its line number in the original file
                element_tag = norm_result.get('parent_element')
                line_num = _find_secret_line_in_original(
                    norm_result['secret'],
                    original_content,
                    element_tag
                )

                if line_num:
                    norm_result['line_number'] = line_num
                    norm_result['detection_method'] = 'normalized_scan_with_lookup'
                else:
                    norm_result['detection_method'] = 'normalized_scan_only'

                merged.append(norm_result)
                seen_secrets[key] = norm_result

        return merged

    # DUAL SCAN APPROACH
    try:
        # Read original content once (needed for both scans and line lookup)
        original_content = read_text_safely(file_path)

        # SCAN 1: Original file (line-based) - captures line numbers
        original_results = scan_original_xml(file_path, plugin_manager)

        # SCAN 2: Normalized file (XML-parsed) - captures element paths and multi-line secrets
        normalized_results = []

        if normalize:
            try:
                # Normalize XML
                xml_content = normalize_xml_content(original_content)

                try:
                    # Parse normalized XML
                    root = ET.fromstring(xml_content)
                except ET.ParseError as e:
                    msg = str(e)
                    # Attempt namespace prefix recovery
                    if ns_recovery and ('unbound prefix' in msg or 'undefined prefix' in msg):
                        try:
                            recovered = _sanitize_unbound_prefixes(xml_content)
                            root = ET.fromstring(recovered)
                            xml_content = recovered
                            print(f"Info: Applied namespace prefix recovery for {file_path}", file=sys.stderr)
                        except ET.ParseError:
                            # If still failing, use only original scan results
                            print(f"Warning: Namespace recovery failed for {file_path}; using original scan only", file=sys.stderr)
                            return original_results
                    else:
                        # Non-namespace parse error: use only original scan
                        print(f"Warning: Parse error for {file_path}: {e}; using original scan only", file=sys.stderr)
                        return original_results

                # Scan the normalized XML tree
                normalized_results = scan_xml_element(root, "", plugin_manager, file_path)

            except Exception as e:
                print(f"Error in normalized scan of {file_path}: {e}; using original scan only", file=sys.stderr)
                return original_results

        # Merge results from both scans (pass original content for line lookup)
        merged_results = _merge_results(original_results, normalized_results, original_content)
        return merged_results

    except Exception as e:
        print(f"Error scanning {file_path}: {e}", file=sys.stderr)
        # Ultimate fallback to line scan on unexpected errors
        try:
            raw = read_text_safely(file_path)
            return _line_fallback(raw)
        except Exception:
            return []


def scan_directory(directory: str, plugin_manager: PluginManager,
                   extensions: List[str] = None, normalize: bool = True,
                   ns_recovery: bool = True) -> List[Dict[str, Any]]:
    """
    Scan a directory for secrets in XML files.

    Args:
        directory: Directory path
        plugin_manager: PluginManager instance
        extensions: File extensions to scan
        normalize: Whether to normalize XML first

    Returns:
        List of all detected secrets
    """
    if extensions is None:
        # Broaden defaults to include common config formats in addition to XML
        extensions = ['.xml', '.config', '.conf', '.properties', '.yaml', '.yml', '.ini', '.cfg']

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
    print(f"Normalization: {'enabled' if normalize else 'disabled'}")
    print(f"File extensions: {', '.join(extensions)}")
    print()

    for file_path in path.rglob('*'):
        if file_path.is_file() and file_path.suffix in extensions:
            file_count += 1
            results = scan_xml_file(str(file_path), plugin_manager, normalize, ns_recovery)
            all_results.extend(results)

            if results:
                print(f"Found {len(results)} secret(s) in: {file_path}")

    print(f"\nScanned {file_count} files with {plugin_manager.get_plugin_count()} plugins")
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

  # List available plugins
  %(prog)s --list-plugins

  # Enable only specific plugins
  %(prog)s /path/to/repo --only xml_password,aws,private_key

  # Disable specific plugins
  %(prog)s /path/to/repo --disable stripe,discord,telegram

  # Custom filtering
  %(prog)s /path/to/repo \
    --include-entities "database_.*" "api_.*" \
    --exclude-entities "test_.*" \
    --output results.json
        """
    )

    parser.add_argument('path', nargs='?', help='File or directory to scan')
    parser.add_argument('--output', '-o', help='Output file (JSON format)')
    parser.add_argument('--extensions', '-e', nargs='+',
                       help='File extensions to scan (default: .xml .config)')

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
                       help='Scan production secrets only')

    # Scanning options
    parser.add_argument('--no-normalize', action='store_true',
                       help='Skip XML normalization (faster but may miss multi-line)')
    parser.add_argument('--disable-unix-crypt', action='store_true',
                       help='Disable Unix crypt hash detection')

    args = parser.parse_args()

    # Handle --list-plugins
    if args.list_plugins:
        print("Available Plugins:")
        print("=" * 80)
        for plugin_info in PluginManager.list_available_plugins():
            enabled = "✓" if plugin_info['enabled_default'] else " "
            print(f"  [{enabled}] {plugin_info['name']:20s} - {plugin_info['description']}")
        print("\n" + "=" * 80)
        print("✓ = Enabled by default")
        print("\nUse --only or --disable to control which plugins run")
        return 0

    # Require path if not listing plugins
    if not args.path:
        parser.error("path is required (unless using --list-plugins)")

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

    # Check if path is file or directory
    input_path = Path(args.path)
    if input_path.is_file():
        # Scan single file
        print(f"Scanning file: {args.path}")
        print(f"Enabled plugins: {', '.join(plugin_manager.get_enabled_plugins())}")
        print(f"Normalization: {'enabled' if not args.no_normalize else 'disabled'}")
        print()
        results = scan_xml_file(str(input_path), plugin_manager, normalize=not args.no_normalize)
        print(f"Found {len(results)} secret(s)")
    else:
        # Scan directory
        results = scan_directory(
            args.path,
            plugin_manager,
            extensions=args.extensions,
            normalize=not args.no_normalize
        )

    # Generate output
    output = {
        'scan_path': args.path,
        'enabled_plugins': plugin_manager.get_enabled_plugins(),
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
    print(f"Summary: Found {len(results)} secrets using {plugin_manager.get_plugin_count()} plugins")
    print(f"{'='*80}")

    # Exit with error code if secrets found
    sys.exit(1 if results else 0)


if __name__ == '__main__':
    main()
