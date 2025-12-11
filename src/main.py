from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pe_parser import get_imports, PEParseError
from .categorize import categorize_imports
from .analyze import compute_capabilities, detect_patterns, describe_patterns
from .report import build_text_report, build_json_report, build_html_report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze Windows executable imports and summarize capabilities."
    )
    parser.add_argument(
        "path",
        help="Path to the PE file (.exe or .dll) to analyze.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format.",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML report file.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed output with additional information.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    path = args.path

    try:
        imports = get_imports(path)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    except PEParseError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}", file=sys.stderr)
        return 1

    categorized = categorize_imports(imports)
    capabilities = compute_capabilities(categorized)
    pattern_ids = detect_patterns(categorized)
    patterns = describe_patterns(pattern_ids)

    if args.verbose:
        print(f"[INFO] Parsed {len(imports)} DLLs with {sum(len(f) for f in imports.values())} total imports.")
        print(f"[INFO] Detected {len(pattern_ids)} behavior patterns.")
        print()

    if args.json:
        report = build_json_report(path, imports, capabilities, patterns)
        print(report)
    elif args.html:
        html_report = build_html_report(path, imports, capabilities, patterns)
        output_file = Path(path).stem + "_analysis.html"
        with open(output_file, "w") as f:
            f.write(html_report)
        if args.verbose:
            print(f"[INFO] HTML report saved to: {output_file}")
        else:
            print(f"HTML report saved to: {output_file}")
    else:
        report = build_text_report(path, imports, capabilities, patterns)
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
