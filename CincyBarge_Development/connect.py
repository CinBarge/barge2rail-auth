import sqlite3
import pandas as pd
import os

def database_creation_import_csv(csv_file_path, db_name, table_name):
    """
    Create a SQLite database and import CSV data into it.
    
    Args:
        csv_file_path (str): Path to the CSV file
        db_name (str): Name of the database file (e.g., 'mydatabase.db')
        table_name (str): Name of the table to create
    """
    
    # Check if CSV file exists
    if not os.path.exists(csv_file_path):
        print(f"Error: CSV file '{csv_file_path}' not found!")
        return False
    
    try:
        # Read CSV file using pandas
        print(f"Reading CSV file: {csv_file_path}")
        df = pd.read_csv(csv_file_path)
        
        # Display basic info about the CSV
        print(f"CSV loaded successfully!")
        print(f"Shape: {df.shape} (rows x columns)")
        print(f"Columns: {list(df.columns)}")
        print("\nFirst 5 rows:")
        print(df.head())
        
        # Create SQLite connection
        print(f"\nCreating database: {db_name}")
        conn = sqlite3.connect(db_name)
        
        # Import DataFrame to SQLite
        print(f"Importing data to table: {table_name}")
        df.to_sql(table_name, conn, if_exists='replace', index=False)
        
        # Verify the import
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        row_count = cursor.fetchone()[0]
        
        print(f"✅ Import successful!")
        print(f"   - Database: {db_name}")
        print(f"   - Table: {table_name}")
        print(f"   - Rows imported: {row_count}")
        
        # Show table schema
        cursor.execute(f"PRAGMA table_info({table_name})")
        schema = cursor.fetchall()
        print(f"\nTable schema:")
        for col in schema:
            print(f"   - {col[1]} ({col[2]})")
        
        # Close connection
        conn.close()
        return True
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return False
    
def query_database(db_name, query):
    """
    Execute a query on the SQLite database.
    
    Args:
        db_name (str): Name of the database file
        query (str): SQL query to execute
    """
    try:
        conn = sqlite3.connect(db_name)
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        print(f"Query error: {str(e)}")
        return None
    
if __name__ == "__main__":
    # Configuration - Update these paths and names
    CSV_FILE_PATH = "C:\\Users\\zx360\\Downloads\\Senco Master - Active - CoilScans.csv"  # Replace with your CSV file path
    DATABASE_NAME = "SencoMaster.db"   # Name for your new database
    TABLE_NAME = "Senco Master"          # Name for your table
    
    # Create database and import CSV
    success = database_creation_import_csv(CSV_FILE_PATH, DATABASE_NAME, TABLE_NAME)
    
    if success:
        # Example queries
        print("\n" + "="*50)
        print("EXAMPLE QUERIES")
        print("="*50)
        
        # Query 1: Show first 10 rows
        print("\nFirst 10 rows:")
        result = query_database(DATABASE_NAME, f"SELECT * FROM {TABLE_NAME} LIMIT 10")
        if result is not None:
            print(result)
        
        # Query 2: Count total rows
        print(f"\nTotal rows in {TABLE_NAME}:")
        result = query_database(DATABASE_NAME, f"SELECT COUNT(*) as total_rows FROM {TABLE_NAME}")
        if result is not None:
            print(result)
        
        # Query 3: Show column names
        print(f"\nColumn information:")
        result = query_database(DATABASE_NAME, f"PRAGMA table_info({TABLE_NAME})")
        if result is not None:
            print(result)