# this file contains the parsing logic for parsing the sqlite databse header information and stores it into a dictionary

import struct
from typing import Dict, Any, BinaryIO
from .const import (
    HEADER_FORMAT,
    HEADER_SIZE,
    SQLITE_MAGIC_STRING,
    MAGIC_STRING,
    PAGE_SIZE,
    WRITE_VERSION,
    READ_VERSION,
    RESERVED_SPACE,
    MAX_PAYLOAD_FRACTION,
    MIN_PAYLOAD_FRACTION,
    LEAF_PAYLOAD_FRACTION,
    FILE_CHANGE_COUNTER,
    DATABASE_SIZE,
    FIRST_FREELIST_PAGE,
    FREELIST_PAGE_COUNT,
    SCHEMA_COOKIE,
    SCHEMA_FORMAT,
    PAGE_CACHE_SIZE,
    LARGEST_ROOT_PAGE,
    TEXT_ENCODING,
    USER_VERSION,
    INCREMENTAL_VACUUM,
    APPLICATION_ID,
    VERSION_VALID_FOR,
    SQLITE_VERSION
)

class SQLiteHeader:
    """Parse and represent SQLite database file header information."""
    
    def __init__(self, file: BinaryIO):
        """Initialize by reading and parsing the header from a file object.
        
        Args:
            file: A file-like object opened in binary mode at position 0
        """
        self.raw_header = file.read(HEADER_SIZE)
        if len(self.raw_header) < HEADER_SIZE:
            raise ValueError("File is too small to be a valid SQLite database")
            
        self._parse_header()
        
    def _parse_header(self) -> None:
        """Parse the raw header bytes into structured data."""
        # Calculate the expected size based on the header format
        expected_size = struct.calcsize(HEADER_FORMAT)
        # Ensure we have enough data
        if len(self.raw_header) < expected_size:
            raise ValueError("File header is too small for parsing")
        # Unpack the header using the correct size
        header_fields = struct.unpack(HEADER_FORMAT, self.raw_header[:expected_size])
        
        # Validate magic string
        if header_fields[MAGIC_STRING] != SQLITE_MAGIC_STRING:
            raise ValueError("Invalid SQLite database file (incorrect magic string)")
            
        # Store header fields (remain the same)
        self.page_size = header_fields[PAGE_SIZE]
        self.write_version = header_fields[WRITE_VERSION]
        self.read_version = header_fields[READ_VERSION]
        self.reserved_space = header_fields[RESERVED_SPACE]
        self.max_payload_fraction = header_fields[MAX_PAYLOAD_FRACTION]
        self.min_payload_fraction = header_fields[MIN_PAYLOAD_FRACTION]
        self.leaf_payload_fraction = header_fields[LEAF_PAYLOAD_FRACTION]
        self.file_change_counter = header_fields[FILE_CHANGE_COUNTER]
        self.database_size_pages = header_fields[DATABASE_SIZE]
        self.first_freelist_page = header_fields[FIRST_FREELIST_PAGE]
        self.freelist_page_count = header_fields[FREELIST_PAGE_COUNT]
        self.schema_cookie = header_fields[SCHEMA_COOKIE]
        self.schema_format = header_fields[SCHEMA_FORMAT]
        self.page_cache_size = header_fields[PAGE_CACHE_SIZE]
        self.largest_root_page = header_fields[LARGEST_ROOT_PAGE]
        self.text_encoding = header_fields[TEXT_ENCODING]
        self.user_version = header_fields[USER_VERSION]
        self.incremental_vacuum = header_fields[INCREMENTAL_VACUUM]
        self.application_id = header_fields[APPLICATION_ID]
        self.version_valid_for = header_fields[VERSION_VALID_FOR]
        self.sqlite_version = header_fields[SQLITE_VERSION]
        
    def to_dict(self) -> Dict[str, Any]:
        """Return header information as a dictionary."""
        return {
            "magic_string": SQLITE_MAGIC_STRING,
            "page_size": self.page_size,
            "write_version": self.write_version,
            "read_version": self.read_version,
            "reserved_space": self.reserved_space,
            "max_payload_fraction": self.max_payload_fraction,
            "min_payload_fraction": self.min_payload_fraction,
            "leaf_payload_fraction": self.leaf_payload_fraction,
            "file_change_counter": self.file_change_counter,
            "database_size_pages": self.database_size_pages,
            "first_freelist_page": self.first_freelist_page,
            "freelist_page_count": self.freelist_page_count,
            "schema_cookie": self.schema_cookie,
            "schema_format": self.schema_format,
            "page_cache_size": self.page_cache_size,
            "largest_root_page": self.largest_root_page,
            "text_encoding": self.text_encoding,
            "user_version": self.user_version,
            "incremental_vacuum": self.incremental_vacuum,
            "application_id": self.application_id,
            "version_valid_for": self.version_valid_for,
            "sqlite_version": self.sqlite_version,
        }
        
    def __str__(self) -> str:
        """Return a human-readable representation of the header."""
        return (
            f"SQLite Database Header:\n"
            f"  Page Size: {self.page_size} bytes\n"
            f"  Database Size: {self.database_size_pages} pages\n"
            f"  Schema Version: {self.schema_cookie}\n"
            f"  Text Encoding: {self._get_text_encoding()}\n"
            f"  Application ID: {self.application_id}\n"
            f"  SQLite Version: {self.sqlite_version}"
        )
        
    def _get_text_encoding(self) -> str:
        """Get human-readable text encoding."""
        encodings = {
            1: "UTF-8",
            2: "UTF-16le",
            3: "UTF-16be"
        }
        return encodings.get(self.text_encoding, f"Unknown ({self.text_encoding})")