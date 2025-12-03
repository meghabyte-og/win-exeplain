from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pefile


class PEParseError(Exception):
    """Custom exception for problems parsing a PE file."""
    pass


def get_imports(path: str | Path) -> Dict[str, List[str]]:
    """
    Parse a PE file and return its imported DLLs and function names.

    Returns a dict:
    {
        "KERNEL32.DLL": ["CreateFileW", "ReadFile", ...],
        "WS2_32.DLL":   ["connect", "send", "recv", ...],
        ...
    }

    Raises:
        FileNotFoundError: if the file does not exist.
        PEParseError: if the file cannot be parsed as a PE.
    """
    path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        pe = pefile.PE(str(path))
    except pefile.PEFormatError as e:
        raise PEParseError(f"Not a valid PE file: {path}") from e

    imports: Dict[str, List[str]] = {}

    # Some binaries may have no import table
    directory = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
    if directory is None:
        return imports

    for entry in directory:
        dll_name_bytes = entry.dll
        dll_name = dll_name_bytes.decode(errors="ignore").upper() if dll_name_bytes else "UNKNOWN"

        funcs: List[str] = []
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode(errors="ignore")
            else:
                # Some imports may be by ordinal only
                func_name = f"ORDINAL_{imp.ordinal}" if imp.ordinal is not None else "UNKNOWN"

            funcs.append(func_name)

        imports[dll_name] = funcs

    return imports
