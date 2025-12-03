from __future__ import annotations

from src.categorize import categorize_imports
from src.analyze import compute_capabilities, detect_patterns


def test_categorize_and_analyze_fake_imports():
    fake_imports = {
        "KERNEL32.DLL": ["CreateFileW", "ReadFile"],
        "WS2_32.DLL": ["connect", "send"],
        "KERNEL32.DLL": ["CreateFileW", "ReadFile"],
        "KERNEL32.DLL": ["CreateFileW", "ReadFile"],
    }

    categorized = categorize_imports(fake_imports)
    capabilities = compute_capabilities(categorized)
    patterns = detect_patterns(categorized)

    # We should at least see file_io and network present
    assert capabilities["file_io"]["present"]
    assert capabilities["network"]["present"]

    # With both file_io and network present, our heuristic should detect network_and_file_io
    assert "network_and_file_io" in patterns
