from db_utils import get_conn

try:
    conn = get_conn()
    print("Connected successfully!")
    conn.close()
except Exception as e:
    print("Connection failed:", e)
