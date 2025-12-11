from __future__ import annotations

from src.categorize import categorize_imports
from src.analyze import compute_capabilities, detect_patterns
from src.pe_parser import get_imports, load_pe


def test_categorize_and_analyze_fake_imports():
    """Test categorization and analysis with fake imports."""
    fake_imports = {
        "KERNEL32.DLL": ["CreateFileW", "ReadFile"],
        "WS2_32.DLL": ["connect", "send"],
    }

    categorized = categorize_imports(fake_imports)
    capabilities = compute_capabilities(categorized)
    patterns = detect_patterns(categorized)

    # We should at least see file_io and network present
    assert capabilities["file_io"]["present"]
    assert capabilities["network"]["present"]

    # With both file_io and network present, our heuristic should detect network_and_file_io
    assert "network_and_file_io" in patterns


def test_notepad_has_imports():
    """
    Smoke test: Verify that PE parsing works on a system binary.
    This test requires Windows with notepad.exe available.
    """
    notepad_path = r"C:\Windows\System32\notepad.exe"
    try:
        imports = get_imports(notepad_path)
        # Verify we got some imports
        assert len(imports) > 0, "Should have found at least some DLL imports"
        # Verify we can access the dict structure
        assert isinstance(imports, dict)
        # Check that at least one DLL was imported with functions
        for dll, funcs in imports.items():
            assert isinstance(funcs, list)
            assert len(funcs) > 0, f"DLL {dll} should have imported functions"
            break  # Just check the first one
    except FileNotFoundError:
        # Skip test if notepad.exe not found
        import pytest
        pytest.skip("notepad.exe not found")
