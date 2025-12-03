from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pe_parser import get_imports, PEParseError
from .categorize import categorize_imports
from .analyze import compute_capabilities, detect_patterns, describe_patterns
from .report import build_text_report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze Windows executable imports and summarize capabilities."
    )
    parser.add_argument(
        "path",
        help="Path to the PE file (.exe or .dll) to analyze.",
    )
    # You can add flags like --json or --html later
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

    report = build_text_report(path, imports, capabilities, patterns)
    print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
