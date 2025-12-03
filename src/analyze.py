from __future__ import annotations

from typing import Dict, List, Set, Tuple

# Human-readable descriptions for capability categories
CATEGORY_DESCRIPTIONS: Dict[str, str] = {
    "file_io": "Can create, read, write, or delete files on disk.",
    "network": "Can communicate over the network (e.g., sockets or HTTP).",
    "registry": "Can read or modify Windows registry keys.",
    "process_injection": "Imports APIs commonly associated with process injection.",
    "process_management": "Can create or manage other processes.",
    "crypto": "Uses cryptographic APIs for encryption, decryption, or key handling.",
    "unknown": "Uses APIs that are not yet categorized.",
}

# Pattern IDs → human-readable text
PATTERN_DESCRIPTIONS: Dict[str, str] = {
    "process_injection_combo": (
        "Process injection combo detected: uses OpenProcess, VirtualAllocEx, "
        "and WriteProcessMemory (classic code injection pattern)."
    ),
    "network_and_file_io": (
        "Has both networking and file I/O capabilities, which may allow downloading "
        "or exfiltrating data."
    ),
    "registry_persistence": (
        "Can modify the registry, which can be used for configuration or persistence."
    ),
}


def compute_capabilities(
    categorized: Dict[str, List[str]]
) -> Dict[str, Dict[str, object]]:
    """
    Build a small structure describing each category:
    {
        "file_io": {
            "present": True,
            "count": 5,
            "examples": ["CreateFileW", "ReadFile"]
        },
        ...
    }
    """
    capabilities: Dict[str, Dict[str, object]] = {}

    for category, funcs in categorized.items():
        if not funcs:
            continue

        capabilities[category] = {
            "present": True,
            "count": len(funcs),
            "examples": sorted(set(funcs))[:5],  # up to 5 example APIs
            "description": CATEGORY_DESCRIPTIONS.get(category, ""),
        }

    # Also explicitly include categories with no functions if needed
    for cat, desc in CATEGORY_DESCRIPTIONS.items():
        if cat not in capabilities:
            capabilities[cat] = {
                "present": False,
                "count": 0,
                "examples": [],
                "description": desc,
            }

    return capabilities


def _flatten_apis(categorized: Dict[str, List[str]]) -> Set[str]:
    """Get a set of all imported API names (original case)."""
    apis: Set[str] = set()
    for funcs in categorized.values():
        apis.update(funcs)
    return apis


def detect_patterns(categorized: Dict[str, List[str]]) -> List[str]:
    """
    Return a list of pattern IDs that were detected based on the categorized imports.

    Pattern IDs correspond to keys in PATTERN_DESCRIPTIONS.
    """
    patterns: List[str] = []
    all_apis = {name.lower() for name in _flatten_apis(categorized)}

    # Process injection combo
    if {"openprocess", "virtualallocex", "writeprocessmemory"} <= all_apis:
        patterns.append("process_injection_combo")

    # Network + file I/O both present
    if categorized.get("network") and categorized.get("file_io"):
        patterns.append("network_and_file_io")

    # Registry modification
    if categorized.get("registry"):
        patterns.append("registry_persistence")

    return patterns


def describe_patterns(pattern_ids: List[str]) -> List[Tuple[str, str]]:
    """
    Convert pattern IDs into (pattern_id, human_description) pairs.
    """
    described: List[Tuple[str, str]] = []
    for pid in pattern_ids:
        text = PATTERN_DESCRIPTIONS.get(pid, "")
        described.append((pid, text))
    return described
