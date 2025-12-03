from __future__ import annotations

from typing import Dict, List, DefaultDict
from collections import defaultdict

# Very small starter mapping.
# You can expand this over time as part of the project.
API_CATEGORIES: Dict[str, str] = {
    # file I/O
    "createfilew": "file_io",
    "createfilea": "file_io",
    "readfile": "file_io",
    "writefile": "file_io",
    "deletefilew": "file_io",
    "deletefilea": "file_io",
    "copyfilew": "file_io",
    "copyfilea": "file_io",

    # networking
    "socket": "network",
    "connect": "network",
    "send": "network",
    "recv": "network",
    "wsastartup": "network",
    "internetopena": "network",
    "internetopenw": "network",
    "internetopenurla": "network",
    "internetopenurlw": "network",
    "winhttpsendrequest": "network",

    # registry
    "regopenkeyexa": "registry",
    "regopenkeyexw": "registry",
    "regcreatekeyexa": "registry",
    "regcreatekeyexw": "registry",
    "regsetvalueexa": "registry",
    "regsetvalueexw": "registry",
    "regdeletevaluea": "registry",
    "regdeletevaluew": "registry",

    # process management / injection-ish
    "openprocess": "process_injection",
    "virtualallocex": "process_injection",
    "writeprocessmemory": "process_injection",
    "createremotethread": "process_injection",

    # process / command execution
    "createprocessa": "process_management",
    "createprocessw": "process_management",
    "winexec": "process_management",
    "shell32.shell_executea": "process_management",  # sometimes appears as full name

    # crypto (example)
    "cryptencrypt": "crypto",
    "cryptdecrypt": "crypto",
    "cryptacquirecontexta": "crypto",
    "cryptacquirecontextw": "crypto",
}


def normalize_api_name(name: str) -> str:
    """
    Normalize an API name for lookup:
    - lowercased
    - strip leading underscores
    """
    name = name.strip()
    while name.startswith("_"):
        name = name[1:]
    return name.lower()


def categorize_imports(imports: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Take the raw imports dict and group functions by category.

    Returns:
    {
        "file_io": ["CreateFileW", "ReadFile", ...],
        "network": ["connect", "send", ...],
        "unknown": ["SomeWeirdFunction", ...],
        ...
    }
    """
    categorized: DefaultDict[str, List[str]] = defaultdict(list)

    for dll, funcs in imports.items():
        for func in funcs:
            key = normalize_api_name(func)
            category = API_CATEGORIES.get(key, "unknown")
            categorized[category].append(func)

    return dict(categorized)
