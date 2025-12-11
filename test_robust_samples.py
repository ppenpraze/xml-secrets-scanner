#!/usr/bin/env python3
"""
Robustness tests for xml-secrets-scanner.

Covers:
- Broken/malformed XML (unbound prefix, bad nesting)
- Plain text and source code files
- Files written in multiple encodings (utf-8, utf-8-sig, cp1252 with NBSP, latin-1, utf-16)

This is a self-contained script (no pytest required). It prints a summary and
exits with non-zero status if any checks fail.
"""

import os
import sys
import tempfile
from pathlib import Path

from scan_xml_with_context import scan_xml_file
from scan_with_plugins import scan_file
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin


def write_text(path: Path, text: str, encoding: str = "utf-8", add_bom: bool = False):
    """Write text to a file with selected encoding. Optionally add BOM for utf-8."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if add_bom and encoding.lower().replace('_', '-') in {"utf-8", "utf8"}:
        with open(path, "wb") as f:
            f.write(b"\xef\xbb\xbf")
            f.write(text.encode("utf-8"))
    else:
        with open(path, "w", encoding=encoding, errors="strict") as f:
            f.write(text)


def expect(condition: bool, message: str, failures: list):
    if condition:
        print(f"✓ {message}")
    else:
        print(f"✗ {message}")
        failures.append(message)


def main() -> int:
    xml_plugin = XMLPasswordPlugin()
    unix_plugin = UnixCryptPlugin()

    failures = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tdir = Path(tmpdir)

        # 1) Malformed XML: unbound prefix (should trigger ns recovery or fallback)
        xml_unbound = (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<conf>\n"
            "  <x:database>\n"  # unknown prefix
            "    <password>RobustPass123!</password>\n"
            "  </x:database>\n"
            "</conf>\n"
        )
        p_unbound = tdir / "broken" / "unbound_prefix.xml"
        write_text(p_unbound, xml_unbound, "utf-8")

        res_unbound = scan_xml_file(str(p_unbound), xml_plugin, unix_plugin, normalize=True, ns_recovery=True)
        expect(any("RobustPass123!" in r.get("line_content", "") for r in res_unbound),
               "Detects secret in XML with unbound prefix (via recovery or fallback)", failures)

        # 2) Malformed XML: bad nesting (forces fallback)
        xml_bad = (
            "<root><item><password>BadNestP@ss</password></item"  # missing closing '>'
        )
        p_bad = tdir / "broken" / "bad_nesting.xml"
        write_text(p_bad, xml_bad, "utf-8")
        res_bad = scan_xml_file(str(p_bad), xml_plugin, unix_plugin, normalize=True, ns_recovery=True)
        expect(any("BadNestP@ss" in r.get("line_content", "") for r in res_bad),
               "Detects secret in badly nested XML (line_fallback)", failures)
        expect(any(r.get("detection_method") == "line_fallback" for r in res_bad),
               "Uses line_fallback for badly nested XML", failures)

        # 3) XML with CDATA containing a password
        xml_cdata = (
            "<config>\n<![CDATA[ api_password = Ultra!Strong#Pass ]]></config>\n"
        )
        p_cdata = tdir / "xml" / "cdata.xml"
        write_text(p_cdata, xml_cdata, "utf-8")
        res_cdata = scan_xml_file(str(p_cdata), xml_plugin, unix_plugin, normalize=True, ns_recovery=True)
        # Robustness goal: ensure no crash and returns a list even if no detection in CDATA
        expect(isinstance(res_cdata, list),
               "Handles XML with CDATA without crashing", failures)

        # 4) Plain text file
        txt = (
            "# sample plain text with a secret\n"
            "db_password = PlainTextPass42\n"
        )
        p_txt = tdir / "text" / "sample.txt"
        write_text(p_txt, txt, "utf-8")
        res_txt = scan_file(str(p_txt), xml_plugin, unix_plugin)
        expect(isinstance(res_txt, list),
               "Scans plain text file without crashing", failures)

        # 5) Source code files (Python / Java) with embedded config strings
        py_src = (
            "# config\nPASSWORD = 'SrcPass_2024!'\nAPI_TOKEN = 'TOKEN_EXAMPLE_123'\n"
        )
        p_py = tdir / "src" / "config.py"
        write_text(p_py, py_src, "utf-8")
        res_py = scan_file(str(p_py), xml_plugin, unix_plugin)
        expect(isinstance(res_py, list),
               "Scans Python source without crashing", failures)

        java_src = (
            "public class App {\n"
            "  // hardcoded (example only)\n"
            "  String dbPassword = \"HardC0ded!\";\n"
            "}\n"
        )
        p_java = tdir / "src" / "App.java"
        write_text(p_java, java_src, "utf-8")
        res_java = scan_file(str(p_java), xml_plugin, unix_plugin)
        expect(isinstance(res_java, list),
               "Scans Java source without crashing", failures)

        # 6) Encoding variants for the same XML content
        xml_content = (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<config><password>Enc0d3d Pass</password></config>\n"
        )
        # utf-8 BOM
        p_utf8_bom = tdir / "enc" / "utf8_bom.xml"
        write_text(p_utf8_bom, xml_content, "utf-8", add_bom=True)
        res_utf8_bom = scan_xml_file(str(p_utf8_bom), xml_plugin, unix_plugin)
        expect(any("Enc0d3d Pass" in r.get("line_content", "") for r in res_utf8_bom),
               "Handles UTF-8 BOM encoded XML", failures)

        # cp1252 with NBSP (0xA0)
        xml_cp1252 = (
            "<config><password>NBSP\u00A0Pass</password></config>\n"
        )
        p_cp1252 = tdir / "enc" / "cp1252_nbsp.xml"
        write_text(p_cp1252, xml_cp1252, "cp1252")
        res_cp1252 = scan_xml_file(str(p_cp1252), xml_plugin, unix_plugin)
        expect(any("NBSP Pass" in r.get("line_content", "") or "NBSP\u00A0Pass" in r.get("line_content", "") for r in res_cp1252),
               "Handles cp1252 encoded XML with NBSP (0xA0)", failures)

        # latin-1
        xml_latin1 = "<config><password>Latïn1-Päss!</password></config>\n"
        p_latin1 = tdir / "enc" / "latin1.xml"
        write_text(p_latin1, xml_latin1, "latin-1")
        res_latin1 = scan_xml_file(str(p_latin1), xml_plugin, unix_plugin)
        expect(any("Lat" in r.get("line_content", "") and "P" in r.get("line_content", "") for r in res_latin1),
               "Handles latin-1 encoded XML", failures)

        # utf-16-le
        p_utf16le = tdir / "enc" / "utf16le.xml"
        write_text(p_utf16le, xml_content, "utf-16-le")
        res_utf16le = scan_xml_file(str(p_utf16le), xml_plugin, unix_plugin)
        expect(any("Enc0d3d Pass" in r.get("line_content", "") for r in res_utf16le),
               "Handles UTF-16 LE encoded XML", failures)

        # Also test line-based scanner on a non-XML extension to ensure generic handling
        conf_text = "password=ConfPass99!\n"
        p_conf = tdir / "etc" / "app.properties"
        write_text(p_conf, conf_text, "utf-8")
        res_conf = scan_file(str(p_conf), xml_plugin, unix_plugin)
        expect(isinstance(res_conf, list),
               "Scans .properties file without crashing", failures)

    print("\n=== Robustness Test Summary ===")
    if failures:
        print(f"Failures: {len(failures)}")
        for f in failures:
            print(f" - {f}")
        return 1
    else:
        print("All checks passed.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
