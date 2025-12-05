# db_utils.py
import os
import psycopg2
import psycopg2.extras
from datetime import datetime

DB_CONFIG = {
    "host": os.environ.get("NEW_DB_HOST", "database-1.c5kuma82sf8e.ap-south-1.rds.amazonaws.com"),
    "port": int(os.environ.get("NEW_DB_PORT", 5432)),
    "dbname": os.environ.get("NEW_DB_NAME", "postgres"),
    "user": os.environ.get("NEW_DB_USER", "postgres"),
    "password": os.environ.get("NEW_DB_PASSWORD", "Ruthvik3234L")
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG)

def _serialize_row(row):
    if not row:
        return None
    r = dict(row)
    for k, v in r.items():
        if isinstance(v, datetime):
            r[k] = v.strftime("%Y-%m-%d %H:%M:%S")
    return r

def _serialize_list(rows):
    return [_serialize_row(r) for r in rows]

# 1) find students (roll/name fuzzy ILIKE)
def find_students_by_query(qtext, limit=20):
    sql = """
    SELECT s.id, s.roll_number, s.batch_year, s.current_semester,
           s.department_id, s.mentor_id,
           u.first_name, u.last_name, u.email
    FROM vmeg.profiles_studentprofile s
    LEFT JOIN vmeg.authentication_user u ON s.user_id = u.id
    WHERE s.roll_number ILIKE %s OR u.first_name ILIKE %s OR u.last_name ILIKE %s
    LIMIT %s;
    """
    like = f"%{qtext}%"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (like, like, like, limit))
            return _serialize_list(cur.fetchall())

# 2) get student by id
def get_student_by_id(student_id):
    sql = """
    SELECT s.id, s.roll_number, s.batch_year, s.current_semester,
           s.department_id, s.mentor_id,
           u.first_name, u.last_name, u.email
    FROM vmeg.profiles_studentprofile s
    LEFT JOIN vmeg.authentication_user u ON s.user_id = u.id
    WHERE s.id = %s;
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (student_id,))
            return _serialize_row(cur.fetchone())

# 3) get mentees of a mentor
def get_mentees(mentor_id):
    sql = """
    SELECT s.id, s.roll_number, s.batch_year, s.current_semester,
           u.first_name, u.last_name, u.email, s.mentor_id
    FROM vmeg.profiles_studentprofile s
    LEFT JOIN vmeg.authentication_user u ON s.user_id = u.id
    WHERE s.mentor_id = %s;
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (mentor_id,))
            return _serialize_list(cur.fetchall())

# 4) certificates
def get_certificates_for_student(student_id):
    sql = """
    SELECT id, title, issuing_organization, file_url,
           ai_summary, credit_points, academic_year,
           status, created_at
    FROM vmeg.achievements_certificate
    WHERE student_id = %s
    ORDER BY created_at DESC;
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (student_id,))
            return _serialize_list(cur.fetchall())

# 5) department
def get_department_by_id(dept_id):
    if not dept_id:
        return None
    sql = "SELECT id, name, code FROM vmeg.academics_department WHERE id = %s;"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (dept_id,))
            return _serialize_row(cur.fetchone())

# 6) count certificates
def count_certificates(student_id):
    sql = "SELECT COUNT(*) AS cnt FROM vmeg.achievements_certificate WHERE student_id = %s;"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (student_id,))
            return cur.fetchone()[0]
