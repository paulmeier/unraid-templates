#!/usr/bin/env python3
"""
Validate Unraid Community Applications XML templates for common
CA policy violations before submission.

Checks:
- Shell injection / command chaining in fields that end up in docker run
- HTML tags inside Overview / Description (CA prefers no HTML tags)
- Affiliate / referral links in URLs
- Suspicious icon formats (e.g. GIF)

Usage:
  python validate_unraid_ca_templates.py [path_to_templates_dir]

If no path is given, it runs against the current directory.
"""

import os
import sys
import re
import xml.etree.ElementTree as ET
from typing import List, Tuple

# Heuristic regexes
SHELL_BAD_CHARS_RE = re.compile(r'[;&`|]|\$\(')
AFFILIATE_PATTERNS = [
    'ref=',
    'affiliate',
    'utm_',
    'tag=',
    'fbclid',
    'campid=',
    'gclid',
]
URL_RE = re.compile(r'https?://\S+')

def find_xml_files(root: str) -> List[str]:
    xml_files = []
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.lower().endswith('.xml'):
                xml_files.append(os.path.join(dirpath, fname))
    return xml_files

def check_shell_injection(value: str) -> bool:
    return bool(SHELL_BAD_CHARS_RE.search(value))

def check_affiliate(url: str) -> bool:
    lower = url.lower()
    return any(p in lower for p in AFFILIATE_PATTERNS)

def get_all_text(node) -> List[str]:
    """Collect text and tail strings for a node and descendants."""
    texts = []
    if node.text:
        texts.append(node.text)
    for child in node:
        texts.extend(get_all_text(child))
        if child.tail:
            texts.append(child.tail)
    return texts

def check_html_in_node(node) -> bool:
    """
    Flag if Overview/Description contain nested tags (child elements)
    or HTML-looking text.
    """
    # If there are child elements, we assume HTML markup is being used.
    if list(node):
        return True

    # Also check for HTML-like patterns in text (&lt;tag&gt;, etc.)
    texts = get_all_text(node)
    html_like_re = re.compile(r'<\s*[a-zA-Z]+[^>]*>|&lt;\s*[a-zA-Z]+[^&]*&gt;')
    return any(html_like_re.search(t) for t in texts if t)

def validate_template(path: str) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        errors.append(f"ERROR: Failed to parse XML: {e}")
        return False, errors

    # Container-level simple fields
    simple_fields = ["Repository", "Registry", "Icon", "Support", "Project", "Name"]
    for field in simple_fields:
        for elem in root.findall(field):
            text = (elem.text or "").strip()
            if not text:
                continue
            if check_shell_injection(text):
                errors.append(f"ERROR in <{field}>: shell-like characters found: '{text}'")

            # Check URL fields for affiliate patterns
            if URL_RE.search(text) and check_affiliate(text):
                errors.append(f"ERROR in <{field}>: affiliate/referral-looking URL detected: '{text}'")

            # Icon format check
            if field == "Icon":
                lower = text.lower()
                if lower.endswith('.gif'):
                    warnings.append(f"WARNING in <Icon>: GIF icon found (animated icons discouraged): '{text}'")

    # Overview and Description HTML checks
    for tag in ["Overview", "Description"]:
        for node in root.findall(tag):
            if check_html_in_node(node):
                warnings.append(
                    f"WARNING in <{tag}>: HTML tags or HTML-like content detected. "
                    f"CA policies recommend not embedding HTML tags."
                )

    # Config elements: check attributes and text for shell injection and affiliate URLs
    for cfg in root.findall("Config"):
        cfg_name = cfg.get("Name", "Unnamed Config")
        # Attributes
        for attr_name, attr_val in cfg.attrib.items():
            val = (attr_val or "").strip()
            if not val:
                continue

            # Shell injection checks
            if check_shell_injection(val):
                errors.append(
                    f"ERROR in <Config Name='{cfg_name}'> attribute '{attr_name}': "
                    f"shell-like characters found: '{val}'"
                )

            # URL affiliate checks
            if URL_RE.search(val) and check_affiliate(val):
                errors.append(
                    f"ERROR in <Config Name='{cfg_name}'> attribute '{attr_name}': "
                    f"affiliate/referral-looking URL detected: '{val}'"
                )

        # Text inside <Config> (description)
        cfg_text = (cfg.text or "").strip()
        if cfg_text:
            if check_shell_injection(cfg_text):
                errors.append(
                    f"ERROR in <Config Name='{cfg_name}'> description: "
                    f"shell-like characters found: '{cfg_text}'"
                )
            if URL_RE.search(cfg_text) and check_affiliate(cfg_text):
                errors.append(
                    f"ERROR in <Config Name='{cfg_name}'> description: "
                    f"affiliate/referral-looking URL detected: '{cfg_text}'"
                )

    # All text nodes for stray HTML tags or affiliate links
    for elem in root.iter():
        for txt in get_all_text(elem):
            if not txt:
                continue
            # We already do more specific checks above, so here just search for URLs in general
            for m in URL_RE.finditer(txt):
                url = m.group(0)
                if check_affiliate(url):
                    errors.append(
                        f"ERROR: affiliate/referral-looking URL detected in text: '{url}'"
                    )

    all_msgs = errors + warnings
    ok = not errors
    if ok:
        all_msgs.append("OK: No blocking CA policy issues detected (heuristic check).")

    return ok, all_msgs

def main():
    if len(sys.argv) > 1:
        base = sys.argv[1]
    else:
        base = "."

    xml_files = find_xml_files(base)
    if not xml_files:
        print(f"No XML templates found under: {base}")
        sys.exit(0)

    overall_ok = True
    for path in xml_files:
        print(f"=== Checking {path} ===")
        ok, msgs = validate_template(path)
        overall_ok = overall_ok and ok
        for msg in msgs:
            print("  " + msg)
        print()

    if not overall_ok:
        print("One or more templates have blocking issues. Please fix them before submitting to CA.")
        sys.exit(1)
    else:
        print("All templates passed the heuristic CA policy checks.")
        sys.exit(0)

if __name__ == "__main__":
    main()
