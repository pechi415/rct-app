import os
import time
import sqlite3
try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None
    DictCursor = None
from flask import g, has_app_context
from config import DB_PATH

_USE_POSTGRES = None

def is_postgres() -> bool:
    """Siempre usar PostgreSQL si DATABASE_URL está definida."""
    return bool(os.environ.get("DATABASE_URL", "").strip())

def insert_and_get_id(conn, sql, params):
    sql2 = sql_params(sql)  # ? -> %s si es Postgres

    # Postgres
    if getattr(conn, "_is_pg", is_postgres()):
        cur = conn.cursor()
        cur.execute(sql2 + " RETURNING id", params)
        new_id = cur.fetchone()[0]
        conn.commit()
        return new_id

    # SQLite
    cur = conn.execute(sql, params)
    conn.commit()
    return cur.lastrowid


def ensure_fatiga_table(conn):
    """Asegura que la tabla fatiga_pausas exista tanto en PG como SQLite."""
    is_pg = is_postgres()
    if is_pg:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS fatiga_pausas (
                id SERIAL PRIMARY KEY,
                reporte_id INTEGER REFERENCES reportes(id) ON DELETE CASCADE,
                reportes_sueno INTEGER DEFAULT 0,
                pausas_activas INTEGER DEFAULT 0
            )
        """)
    else:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fatiga_pausas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporte_id INTEGER NOT NULL,
                reportes_sueno INTEGER DEFAULT 0,
                pausas_activas INTEGER DEFAULT 0,
                FOREIGN KEY(reporte_id) REFERENCES reportes(id) ON DELETE CASCADE
            )
        """)
    conn.commit()


def get_db_connection():
    database_url = os.environ.get("DATABASE_URL")

    if database_url:
        # Render / PostgreSQL - SIEMPRE usar Postgres si DATABASE_URL existe
        
        # Asegurar sslmode=require para conexiones a la nube (Supabase)
        if "sslmode=require" not in database_url:
            if "?" in database_url:
                database_url += "&sslmode=require"
            else:
                database_url += "?sslmode=require"
                
        # Aumentar timeout por si el PgBouncer de Supabase AWS tarda en despertar 
        for attempt in range(3):
            try:
                conn = psycopg2.connect(database_url, cursor_factory=DictCursor, connect_timeout=15)
                conn.autocommit = True  # <-- CLAVE
                ensure_fatiga_table(conn)
                return conn
            except psycopg2.OperationalError as e:
                # Si falla intentamos reconectar tras una brevísima pausa, en caso el pooler esté frío
                if attempt == 2:
                    raise e
                time.sleep(1)
                
    else:
        # Local / SQLite
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        ensure_fatiga_table(conn)
        return conn


def sql_params(query: str) -> str:
    """
    Convierte placeholders de SQLite (?) a psycopg2 (%s) cuando estamos en Postgres.
    En SQLite deja la query igual.
    """
    if is_postgres():
        return query.replace("?", "%s")
    return query


class DBConnWrapper:
    def __init__(self, raw_conn, is_pg: bool):
        self._conn = raw_conn
        self._is_pg = is_pg

    def execute(self, query: str, params=()):
        if self._is_pg:
            cur = self._conn.cursor()
            cur.execute(sql_params(query), params or ())
            return cur
        else:
            return self._conn.execute(query, params or ())

    def fetchval(self, query: str, params=(), default=None):
        cur = self.execute(query, params)
        row = cur.fetchone()
        if row is None:
            return default
        try:
            return row[0]
        except Exception:
            if hasattr(row, "keys") and row.keys():
                return row[list(row.keys())[0]]
            return default

    def commit(self):
        return self._conn.commit()

    def close(self):
        return self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        # Emular autocommit como lo hace PostgreSQL en Render
        if exc_type is None and not self._is_pg:
            try:
                self.commit()
            except Exception:
                pass
        # ✅ NO cerrar aquí, porque get_conn() la guarda en g y teardown la cierra.
        return False


def _open_conn():
    # Render / PostgreSQL
    if is_postgres():
        raw = get_db_connection()  # ya viene con RealDictCursor
        return DBConnWrapper(raw, is_pg=True)

    # Local / SQLite
    raw = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA journal_mode=WAL;")
    raw.execute("PRAGMA synchronous=NORMAL;")
    return DBConnWrapper(raw, is_pg=False)


def get_conn():
    # Dentro de Flask (request): usar g
    if has_app_context():
        if "db" not in g:
            g.db = _open_conn()
        return g.db

    # Fuera de Flask (inicio del programa / scripts)
    return _open_conn()


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass


def init_app(app):
    app.teardown_appcontext(close_db)
