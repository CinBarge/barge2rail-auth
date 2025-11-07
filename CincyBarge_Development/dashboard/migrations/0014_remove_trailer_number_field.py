
from django.db import migrations, connection


def remove_trailer_number_if_exists(apps, schema_editor):
    """Remove trailer_number column if it exists in the database"""
    db_vendor = connection.vendor
    
    with connection.cursor() as cursor:
        # Check if column exists based on database type
        if db_vendor == 'postgresql':
            # PostgreSQL specific query
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='dashboard_billoflading' AND column_name='trailer_number'
            """)
            column_exists = cursor.fetchone() is not None
            
            if column_exists:
                # PostgreSQL supports DROP COLUMN
                cursor.execute("ALTER TABLE dashboard_billoflading DROP COLUMN trailer_number")
                
        elif db_vendor == 'sqlite':
            # SQLite specific query
            cursor.execute("PRAGMA table_info(dashboard_billoflading)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'trailer_number' in columns:
                # SQLite doesn't support DROP COLUMN directly in older versions
                # We need to recreate the table without the column
                cursor.execute("""
                    CREATE TEMPORARY TABLE billoflading_backup AS
                    SELECT id, bill_number, supplier_id, template_id, shipper_name, 
                           shipper_address, consignee_name, consignee_address, origin, 
                           destination, carrier, vessel_name, container_number, seal_number,
                           freight_charges, total_value, status, created_at, created_by_id,
                           confirmed_at, delivery_date, completed_at, pdf_file, notes
                    FROM dashboard_billoflading
                """)
                
                cursor.execute("DROP TABLE dashboard_billoflading")
                
                cursor.execute("""
                    CREATE TABLE dashboard_billoflading (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        bill_number VARCHAR(50) NOT NULL UNIQUE,
                        supplier_id INTEGER NOT NULL REFERENCES dashboard_supplier(id),
                        template_id INTEGER REFERENCES dashboard_billofladingtemplate(id),
                        shipper_name VARCHAR(255),
                        shipper_address TEXT,
                        consignee_name VARCHAR(255),
                        consignee_address TEXT,
                        origin VARCHAR(255),
                        destination VARCHAR(255),
                        carrier VARCHAR(255),
                        vessel_name VARCHAR(255),
                        container_number VARCHAR(100),
                        seal_number VARCHAR(100),
                        freight_charges DECIMAL(10,2),
                        total_value DECIMAL(12,2) NOT NULL DEFAULT 0,
                        status VARCHAR(20) NOT NULL DEFAULT 'draft',
                        created_at DATETIME NOT NULL,
                        created_by_id INTEGER REFERENCES auth_user(id),
                        confirmed_at DATETIME,
                        delivery_date DATE,
                        completed_at DATETIME,
                        pdf_file VARCHAR(100),
                        notes TEXT
                    )
                """)
                
                cursor.execute("""
                    INSERT INTO dashboard_billoflading
                    SELECT * FROM billoflading_backup
                """)
                
                cursor.execute("DROP TABLE billoflading_backup")


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0013_add_field_mapping_to_bol_template'),
    ]

    operations = [
        migrations.RunPython(remove_trailer_number_if_exists, migrations.RunPython.noop),
    ]
