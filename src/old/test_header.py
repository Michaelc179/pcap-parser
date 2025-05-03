import sys
from src import SQLiteHeader

def main(db_path):
    try:
        with open(db_path, 'rb') as f:
            header = SQLiteHeader(f)
            print("Header parsed successfully!")
            print(header)  # Uses __str__ method
            
            # Access individual properties
            print(f"\nPage size: {header.page_size} bytes")
            print(f"Encoding: {header._get_text_encoding()}")
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <database.db>")
        sys.exit(1)
    main(sys.argv[1])