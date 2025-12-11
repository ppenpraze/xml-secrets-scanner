#!/usr/bin/env python3
"""
XML Normalizer for Secret Detection

Normalizes XML files to ensure all elements are on single lines,
making them compatible with line-based secret detection.

This script:
1. Parses XML files
2. Reformats them so each element is on a single line
3. Preserves the XML structure
4. Makes multi-line values detectable by the secret scanner
"""

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


def normalize_xml_content(xml_content: str) -> str:
    """
    Normalize XML content to single-line elements.

    Args:
        xml_content: Raw XML content as string

    Returns:
        Normalized XML content with elements on single lines
    """
    try:
        # Parse the XML
        root = ET.fromstring(xml_content)

        # Convert back to string with minimal formatting
        # Use method='xml' to preserve XML declaration
        normalized = ET.tostring(root, encoding='unicode', method='xml')

        # Add newlines between top-level elements for readability
        # but keep each element and its content on one line
        lines = []
        depth = 0
        current_line = ""

        i = 0
        while i < len(normalized):
            char = normalized[i]
            current_line += char

            if char == '<':
                if i + 1 < len(normalized) and normalized[i + 1] == '/':
                    # Closing tag
                    depth -= 1
                elif i + 1 < len(normalized) and normalized[i + 1] != '?' and normalized[i + 1] != '!':
                    # Opening tag (not XML declaration or comment)
                    depth += 1
            elif char == '>':
                # Check if self-closing
                if i > 0 and normalized[i - 1] == '/':
                    depth -= 1

                # Add newline after closing tags at depth 1 (direct children of root)
                if depth == 1 and i + 1 < len(normalized) and normalized[i + 1] == '<':
                    if i + 2 < len(normalized) and normalized[i + 2] == '/':
                        # Next is a closing tag, keep on same line
                        pass
                    else:
                        current_line += '\n'
                        lines.append(current_line)
                        current_line = ""
                        i += 1
                        continue

            i += 1

        if current_line:
            lines.append(current_line)

        return ''.join(lines)

    except ET.ParseError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        return xml_content


def normalize_xml_file(input_file: str, output_file: Optional[str] = None,
                       preserve_original: bool = True) -> bool:
    """
    Normalize an XML file.

    Args:
        input_file: Path to input XML file
        output_file: Path to output file (if None, creates .normalized.xml)
        preserve_original: If True, keeps original file

    Returns:
        True if successful, False otherwise
    """
    input_path = Path(input_file)

    if not input_path.exists():
        print(f"Error: File not found: {input_file}", file=sys.stderr)
        return False

    # Determine output file
    if output_file is None:
        output_path = input_path.parent / f"{input_path.stem}.normalized{input_path.suffix}"
    else:
        output_path = Path(output_file)

    try:
        # Read original XML
        with open(input_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()

        # Check for XML declaration
        has_declaration = xml_content.strip().startswith('<?xml')

        # Normalize
        normalized = normalize_xml_content(xml_content)

        # Add XML declaration if it was present
        if has_declaration and not normalized.startswith('<?xml'):
            normalized = '<?xml version="1.0" encoding="UTF-8"?>\n' + normalized

        # Write normalized XML
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(normalized)

        print(f"✓ Normalized: {input_file} -> {output_path}")
        return True

    except Exception as e:
        print(f"Error normalizing {input_file}: {e}", file=sys.stderr)
        return False


def normalize_directory(directory: str, output_dir: Optional[str] = None,
                        recursive: bool = True, pattern: str = "*.xml") -> int:
    """
    Normalize all XML files in a directory.

    Args:
        directory: Input directory path
        output_dir: Output directory (if None, creates files alongside originals)
        recursive: Whether to scan recursively
        pattern: File pattern to match

    Returns:
        Number of files normalized
    """
    dir_path = Path(directory)

    if not dir_path.exists() or not dir_path.is_dir():
        print(f"Error: Directory not found: {directory}", file=sys.stderr)
        return 0

    # Create output directory if specified
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

    # Find XML files
    if recursive:
        files = dir_path.rglob(pattern)
    else:
        files = dir_path.glob(pattern)

    count = 0
    for file_path in files:
        if output_dir:
            # Preserve directory structure in output
            rel_path = file_path.relative_to(dir_path)
            out_file = Path(output_dir) / rel_path
            out_file.parent.mkdir(parents=True, exist_ok=True)
            normalize_xml_file(str(file_path), str(out_file))
        else:
            normalize_xml_file(str(file_path))
        count += 1

    return count


def main():
    parser = argparse.ArgumentParser(
        description='Normalize XML files for secret detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Normalize single file
  %(prog)s config.xml

  # Normalize to specific output
  %(prog)s config.xml -o normalized.xml

  # Normalize all XML files in directory
  %(prog)s /path/to/configs -d

  # Normalize recursively to output directory
  %(prog)s /path/to/repo -d -r -o /path/to/normalized
        """
    )

    parser.add_argument('input', help='Input file or directory')
    parser.add_argument('-o', '--output', help='Output file or directory')
    parser.add_argument('-d', '--directory', action='store_true',
                       help='Process directory instead of single file')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Process directories recursively')
    parser.add_argument('-p', '--pattern', default='*.xml',
                       help='File pattern for directory mode (default: *.xml)')

    args = parser.parse_args()

    if args.directory:
        count = normalize_directory(
            args.input,
            args.output,
            recursive=args.recursive,
            pattern=args.pattern
        )
        print(f"\n✓ Normalized {count} XML files")
    else:
        if normalize_xml_file(args.input, args.output):
            print("✓ Done")
        else:
            sys.exit(1)


if __name__ == '__main__':
    main()
