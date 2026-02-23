import sys
import psycopg2

# =========================================================
# CONFIGURACIÓN
# =========================================================
# Pega aquí exactamente LA MISMA URL de Supabase que tienes en Render:
DATABASE_URL = ""

def migrar_usuarios():
    if not DATABASE_URL or "[YOUR-PASSWORD]" in DATABASE_URL:
        print("❌ ERROR: Debes configurar correctamente la variable DATABASE_URL.")
        sys.exit(1)

    try:
        print("⏳ Conectando a Supabase para migración de cambios...")
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        cur = conn.cursor()
        
        # 1. Agregar la columna
        print("🏗️  Agregando columna 'debe_cambiar_pass' a la tabla users...")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS debe_cambiar_pass SMALLINT NOT NULL DEFAULT 0;")
        
        # 2. Hacer que cualquier usuario actual (como el Admin) NO necesite cambiar su contraseña. 
        # (Esto garantiza que el Admin no se quede bloqueado)
        cur.execute("UPDATE users SET debe_cambiar_pass = 0;")
        
        print("✅ ¡Éxito! Migración completada. La base de datos ya está lista para forzar cambios de contraseña en los nuevos usuarios.")
        
    except Exception as e:
        print("❌ Error inesperado:", e)
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

if __name__ == "__main__":
    migrar_usuarios()
