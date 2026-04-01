import os
import re

# Endpoints por blueprint (Audited from NodeNames/Function Names)
BLUEPRINTS = {
    'auth': ['login', 'logout', 'cambiar_password'],
    'admin': ['admin_usuarios', 'admin_usuario_nuevo', 'admin_usuario_editar', 'admin_usuario_eliminar'],
    'reportes': [
        'ver_reportes', 'nuevo_reporte', 'editar_reporte', 'eliminar_reporte', 
        'reporte_pdf', 'resumen', 'reporte_inicio', 'cerrar_reporte', 
        'reabrir_reporte', 'editar_fecha_reporte'
    ],
    'gerencia': ['index'],
    'secciones': [
        'gestion_areas', 'editar_item_gestion', 'eliminar_item_gestion',
        'buses_bahias', 'editar_item_buses', 'eliminar_item_buses',
        'equipos_varados', 'editar_item_varados', 'eliminar_item_varados',
        'ausentismo', 'editar_item_ausentismo', 'eliminar_item_ausentismo',
        'bombas', 'editar_bomba', 'eliminar_bomba',
        'dist_camiones', 'editar_dist_camiones', 'eliminar_dist_camiones',
        'equipo_liviano', 'editar_equipo_liviano', 'eliminar_equipo_liviano', 'equipo_liviano_todas_ok',
        'distribucion_personal', 'editar_personal', 'eliminar_personal',
        'otras_areas', 'editar_otras_areas', 'eliminar_otras_areas',
        'entrenamiento_personal', 'editar_entrenamiento_personal', 'eliminar_entrenamiento_personal',
        'luminarias', 'editar_luminaria', 'eliminar_luminaria',
        'contactos_operadores', 'editar_contacto_operador', 'eliminar_contacto_operador',
        'seguridad', 'seguridad_obs_editar', 'seguridad_obs_eliminar',
        'seguridad_charla_editar', 'seguridad_charla_eliminar',
        'first_last', 'editar_first_last', 'eliminar_first_last',
        'pts_divulgacion', 'pts_editar', 'pts_eliminar',
        'comentarios_turno', 'comentarios_editar', 'comentarios_eliminar',
        'supervisores_turno', 'editar_supervisor_turno', 'eliminar_supervisor_turno',
        'fatiga', 'editar_item_fatiga', 'eliminar_item_fatiga'
    ]
}

# Alias mapping (if templates use a different name than function name)
ALIASES = {
    'reporte_pdf': 'reportes.reporte_pdf',
    'resumen': 'reportes.resumen',
    # Add any other aliases if found
}

REVERSE_MAP = {}
for bp, endpoints in BLUEPRINTS.items():
    for ep in endpoints:
        REVERSE_MAP[ep] = bp

def fix_content(content):
    # Match url_for("endpoint", ...) o url_for('endpoint', ...)
    def replacer(match):
        quote = match.group(1)
        endpoint = match.group(2)
        
        # Ignorar si ya tiene prefijo o si es 'static'
        if '.' in endpoint or endpoint == 'static':
            return match.group(0)
            
        if endpoint in REVERSE_MAP:
            return f'url_for({quote}{REVERSE_MAP[endpoint]}.{endpoint}{quote}'
        
        return match.group(0)

    # Regex para url_for
    pattern = r'url_for\((["\'])([^"\']+)\1'
    return re.sub(pattern, replacer, content)

# Archivos a procesar
project_root = r'C:\Users\Asus\Desktop\Python\rct_app'
dirs_to_scan = [
    os.path.join(project_root, 'blueprints'),
    os.path.join(project_root, 'templates'),
    project_root # Para app.py
]

for d in dirs_to_scan:
    for root, _, files in os.walk(d):
        for file in files:
            if file.endswith(('.py', '.html')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    new_content = fix_content(content)
                    
                    if new_content != content:
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        print(f"Fixed: {file}")
                except Exception as e:
                    print(f"Error processing {file}: {e}")
