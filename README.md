# sqlite-parser

## Overview
This project provides tools for parsing and analyzing SQLite database files at a low level. The initial implementation i've done so far focuses on reading and interpreting the SQLite database header, with plans to expand to full database parsing of <the artifact we will choose>

## Project Structure

```
sqlite-parser/
│
├── parser/
│ ├── init.py
│ ├── header.py # Main header parsing logic
│ └── const.py # Constants for header fields
│
├── test_files/ # Sample SQLite databases for testing
│ └── master.db # Example test file, eventually we'll add the actual artifact we're using
|
├── test_header.py # Tests for header parsing
├── README.md # This file
└── requirements.txt # Python dependencies
```

## Current Components

### Header Parser (`header.py`)
- Parses the first 100 bytes of SQLite files
- Validates the SQLite magic string
- Extracts all header fields into a dictionary
- Provides human-readable output

### Constants (`const.py`)
- Contains all header field positions and formats
- Defines the SQLite magic string
- Provides reference values for header fields

## Getting Started

```bash
pip install -r requirements.txt
python test_header.py test_files\master.db # or any other database file
```

## Example Ouput - Header Parsing
```python
SQLite Database Header:
  Page Size: 4096 bytes
  Database Size: 5 pages
  Schema Version: 1
  Text Encoding: UTF-8
  Application ID: 0
  SQLite Version: 3034000
```