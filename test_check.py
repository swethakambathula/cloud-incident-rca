import sqlite3
conn = sqlite3.connect('data/cloud_rca.db')
cursor = conn.cursor()
cursor.execute("SELECT id FROM incidents WHERE id LIKE 'INC-TEST%' OR id LIKE 'INC-005%'")
print(cursor.fetchall())
cursor.execute("SELECT id FROM incidents WHERE id = 'INC-003-BAD-DEPLOYMENT'")
print(cursor.fetchall())
conn.close()