from __future__ import annotations

import json
from typing import Dict, List, Tuple


def build_json_report(
    path: str,
    imports: Dict[str, List[str]],
    capabilities: Dict[str, Dict[str, object]],
    patterns: List[Tuple[str, str]],
) -> str:
    """
    Build a JSON report.
    """
    report_data = {
        "file": path,
        "total_imports": sum(len(funcs) for funcs in imports.values()),
        "imported_dlls": list(imports.keys()),
        "capabilities": capabilities,
        "detected_patterns": [pid for pid, _ in patterns],
        "pattern_descriptions": {pid: text for pid, text in patterns},
    }
    return json.dumps(report_data, indent=2)


def build_html_report(
    path: str,
    imports: Dict[str, List[str]],
    capabilities: Dict[str, Dict[str, object]],
    patterns: List[Tuple[str, str]],
) -> str:
    """
    Build an HTML report.
    """
    html_lines: List[str] = []
    html_lines.append("<!DOCTYPE html>")
    html_lines.append("<html>")
    html_lines.append("<head>")
    html_lines.append("<meta charset='utf-8'>")
    html_lines.append("<title>PE Analysis Report</title>")
    html_lines.append("<style>")
    html_lines.append("body { font-family: Arial, sans-serif; margin: 20px; }")
    html_lines.append("h1 { color: #333; }")
    html_lines.append("h2 { color: #666; border-bottom: 2px solid #ddd; padding-bottom: 5px; }")
    html_lines.append(".capability { margin: 10px 0; padding: 10px; background-color: #f5f5f5; border-left: 4px solid #0078d4; }")
    html_lines.append(".pattern { margin: 10px 0; padding: 10px; background-color: #fff3cd; border-left: 4px solid #ffc107; }")
    html_lines.append("table { width: 100%; border-collapse: collapse; margin: 10px 0; }")
    html_lines.append("th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }")
    html_lines.append("th { background-color: #f5f5f5; }")
    html_lines.append("</style>")
    html_lines.append("</head>")
    html_lines.append("<body>")
    html_lines.append(f"<h1>PE Analysis Report</h1>")
    html_lines.append(f"<p><strong>File:</strong> {path}</p>")

    total_imports = sum(len(funcs) for funcs in imports.values())
    html_lines.append(f"<p><strong>Total Imported APIs:</strong> {total_imports}</p>")
    html_lines.append(f"<p><strong>Imported DLLs:</strong> {', '.join(sorted(imports.keys())) or 'None'}</p>")

    html_lines.append("<h2>Capability Summary</h2>")
    for category, info in capabilities.items():
        if not info["present"]:
            continue
        examples = info["examples"]
        example_str = ", ".join(examples) if examples else "N/A"
        html_lines.append(f"<div class='capability'>")
        html_lines.append(f"<strong>{category}:</strong> {info['description']} ")
        html_lines.append(f"(count={info['count']}, examples: {example_str})")
        html_lines.append(f"</div>")

    if all(not info["present"] for info in capabilities.values()):
        html_lines.append("<p>No categorized capabilities detected (all imports unknown).</p>")

    html_lines.append("<h2>Detected Behavior Patterns</h2>")
    if not patterns:
        html_lines.append("<p>None detected (based on current heuristic rules).</p>")
    else:
        for pid, text in patterns:
            html_lines.append(f"<div class='pattern'>")
            if text:
                html_lines.append(f"<strong>{pid}:</strong> {text}")
            else:
                html_lines.append(f"<strong>{pid}</strong>")
            html_lines.append(f"</div>")

    html_lines.append("<h2>Imported DLLs and Functions</h2>")
    html_lines.append("<table>")
    html_lines.append("<tr><th>DLL</th><th>Functions</th></tr>")
    for dll, funcs in sorted(imports.items()):
        html_lines.append(f"<tr><td>{dll}</td><td>{', '.join(sorted(funcs))}</td></tr>")
    html_lines.append("</table>")

    html_lines.append("<hr>")
    html_lines.append("<p><em>This analysis is heuristic and based only on statically imported APIs. ")
    html_lines.append("Dynamically resolved APIs or packed/obfuscated binaries may hide behavior.</em></p>")
    html_lines.append("</body>")
    html_lines.append("</html>")

    return "\n".join(html_lines)


def build_text_report(
    path: str,
    imports: Dict[str, List[str]],
    capabilities: Dict[str, Dict[str, object]],
    patterns: List[Tuple[str, str]],
) -> str:
    """
    Build a human-readable text report.
    """
    lines: List[str] = []

    lines.append(f"File: {path}")
    lines.append("")

    total_imports = sum(len(funcs) for funcs in imports.values())
    lines.append(f"Total imported APIs: {total_imports}")
    lines.append(f"Imported DLLs: {', '.join(sorted(imports.keys())) or 'None'}")
    lines.append("")

    lines.append("== Capability Summary ==")
    for category, info in capabilities.items():
        if not info["present"]:
            continue
        examples = info["examples"]
        example_str = ", ".join(examples) if examples else "N/A"
        lines.append(
            f"- {category}: {info['description']} "
            f"(count={info['count']}, examples: {example_str})"
        )

    # Show if everything was unknown
    if all(not info["present"] for info in capabilities.values()):
        lines.append("- No categorized capabilities detected (all imports unknown).")

    lines.append("")
    lines.append("== Detected Behavior Patterns ==")
    if not patterns:
        lines.append("None detected (based on current heuristic rules).")
    else:
        for pid, text in patterns:
            if text:
                lines.append(f"- {text}")
            else:
                lines.append(f"- {pid}")

    lines.append("")
    lines.append("== Notes ==")
    lines.append(
        "This analysis is heuristic and based only on statically imported APIs. "
        "Dynamically resolved APIs or packed/obfuscated binaries may hide behavior."
    )

    return "\n".join(lines)
