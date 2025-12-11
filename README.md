# win-exeplain

**CSE598 Course Assignment**

## LLM Disclosure

This project was developed in part using GitHub Copilot (Claude Haiku 4.5) for code generation. The following components were implemented with AI assistance in this session:
- Argument parsing setup in `main.py` with `--json`, `--html`, and `--verbose` flags
- JSON and HTML report generation in `report.py`
- Clean up the code (to look neater with necessary comments)

## Project Overview

`win-exeplain` is a Python-based Windows executable analysis tool that parses PE (Portable Executable) files and extracts imported DLLs and API functions. The tool analyzes Windows binaries to identify their dependencies and categorize their likely capabilities based on API function imports.

## Objectives

- Parse PE file headers and import tables from Windows executables (.exe, .dll files)
- Extract all imported Dynamic Link Libraries (DLLs) and their associated functions
- Categorize imported functions by functionality (e.g., file operations, network operations, registry access)
- Generate analysis reports in multiple formats (plain text, JSON, HTML)
- Handle edge cases such as packed binaries, missing import tables, and malformed files
- Provide user-friendly error messages and verbose logging capabilities

## Features

### Core Functionality

1. **PE File Parsing** (`pe_parser.py`)
   - Load and parse Windows PE files using the `pefile` library
   - Extract import tables from executable files
   - Handle Unicode/bytes conversions for DLL and function names
   - Gracefully handle edge cases (packed binaries, no imports, corrupted files)

2. **API Categorization** (`categorize.py`)
   - Categorize imported functions by their functionality
   - Identify capabilities like file I/O, networking, registry access, process management, etc.
   - Generate human-readable summaries of executable behavior

3. **Report Generation** (`report.py`)
   - Generate analysis reports in multiple formats
   - Support plain text, JSON, and HTML output options
   - Include detailed import information and categorization results

4. **Command-Line Interface** (`main.py`)
   - User-friendly argument parsing with argparse
   - Support for positional argument: target executable path
   - Optional flags:
     - `--json`: Output results in JSON format
     - `--html`: Generate HTML report file
     - `--verbose`: Enable detailed output with additional information

## Project Structure

```
win-exeplain/
├── src/
│   ├── __init__.py
│   ├── main.py              # CLI entry point with argument parsing
│   ├── pe_parser.py         # PE file parsing and import extraction
│   ├── categorize.py        # Function categorization logic
│   ├── analyze.py           # Analysis orchestration
│   ├── report.py            # Report generation
│   └── tests/
│       ├── __init__.py
│       └── test_basic.py    # Unit tests
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Usage

### Installation

Install required dependencies:
```bash
pip install -r requirements.txt
```

### Running the Tool

```bash
# Basic analysis with console output
python -m src.main sample.exe

# Generate JSON output
python -m src.main sample.exe --json

# Generate HTML report
python -m src.main sample.exe --html

# Enable verbose output for debugging
python -m src.main sample.exe --verbose
```

### Example

```bash
python -m src.main C:\Windows\System32\notepad.exe --json --verbose
```

## Implementation Details

### Phase 1: PE Import Parsing

The `pe_parser.py` module implements:

- **`load_pe(path: str) -> pefile.PE`**: Loads a PE file and returns a pefile object
- **`get_imports(path: str) -> dict[str, list[str]]`**: Extracts imports in the format:
  ```python
  {
      "KERNEL32.DLL": ["CreateFileW", "ReadFile", "WriteFile", ...],
      "WS2_32.DLL": ["connect", "send", "recv", ...],
      "ADVAPI32.DLL": ["RegOpenKeyEx", "RegQueryValueEx", ...]
  }
  ```

**Error Handling:**
- File not found → User-friendly error message
- Invalid PE file → Appropriate error logging
- No import table → Returns empty dict with notification
- Encoding issues → Automatic bytes-to-string conversion

### Testing

The project includes unit tests in `tests/test_basic.py`:

- Smoke test to verify PE parsing functionality
- Tests against system binaries (e.g., notepad.exe)
- Validation of import extraction accuracy

Run tests with:
```bash
python -m pytest tests/
```

## Dependencies

- **pefile**: PE file parsing library for Windows executables
- **pytest**: Testing framework (optional, for unit tests)

See `requirements.txt` for full dependency list.

## Technical Notes

- The tool uses the `pefile` library to parse PE file headers and import tables
- Supports both x86 and x64 executables
- Handles both ASCII and Unicode import names
- Compatible with various PE file types (.exe, .dll, .sys, etc.)

## Limitations & Future Work

- Currently does not analyze packed or obfuscated binaries beyond detecting missing imports
- Does not perform dynamic analysis or behavior monitoring
- Future versions could include:
  - Support for API behavior descriptions
  - Export table analysis
  - Resource section analysis
  - Integration with threat intelligence databases
