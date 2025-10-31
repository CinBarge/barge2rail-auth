#!/usr/bin/env python
"""
Test Neon PostgreSQL connection before deployment.
Run this locally to verify your connection string works.

Usage:
    python test_neon_connection.py "your-neon-connection-string"
"""

import sys
from urllib.parse import urlparse

import psycopg2


def test_neon_connection(connection_string):
    """Test connection to Neon PostgreSQL"""

    # Handle both postgres:// and postgresql:// schemes
    if connection_string.startswith("postgres://"):
        connection_string = connection_string.replace("postgres://", "postgresql://", 1)

    print(f"Testing connection to Neon...")
    print(f"Connection string format: {connection_string[:30]}...")

    try:
        # Parse the connection string
        result = urlparse(connection_string)

        # Connect to Neon
        conn = psycopg2.connect(
            database=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname,
            port=result.port or 5432,
            sslmode="require",  # Neon requires SSL
        )

        # Test the connection
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()

        print("\n✅ SUCCESS! Connected to Neon PostgreSQL")
        print(f"Database version: {version[0][:50]}...")
        print(f"Host: {result.hostname}")
        print(f"Database: {result.path[1:]}")
        print(f"User: {result.username}")
        print("\nYour connection string is valid and working!")
        print("You can safely use this in your Render deployment.")

        cursor.close()
        conn.close()
        return True

    except psycopg2.OperationalError as e:
        print("\n❌ FAILED to connect to Neon")
        print(f"Error: {e}")
        print("\nTroubleshooting:")
        print("1. Check your connection string format")
        print("2. Ensure it includes ?sslmode=require")
        print("3. Verify database is active in Neon console")
        print("4. Try using 'Pooled connection' string from Neon")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: python test_neon_connection.py "your-neon-connection-string"')
        print("\nExample:")
        print(
            'python test_neon_connection.py "postgresql://user:pass@host.neon.tech/db?sslmode=require"'
        )
        sys.exit(1)

    connection_string = sys.argv[1]
    success = test_neon_connection(connection_string)
    sys.exit(0 if success else 1)
