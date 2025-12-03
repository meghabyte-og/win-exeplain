from __future__ import annotations

from typing import Dict, List, Tuple


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
