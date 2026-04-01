import os

template_dir = r'C:\Users\Asus\Desktop\Python\rct_app\templates'

# Mapeo de errores manuales previos a nombres de función reales en secciones.py
CORRECTIONS = {
    'secciones.editar_item_supervisores': 'secciones.editar_supervisor_turno',
    'secciones.eliminar_item_supervisores': 'secciones.eliminar_supervisor_turno',
    'secciones.editar_item_seguridad_obs': 'secciones.seguridad_obs_editar',
    'secciones.eliminar_item_seguridad_obs': 'secciones.seguridad_obs_eliminar',
    'secciones.editar_item_seguridad_charlas': 'secciones.seguridad_charla_editar',
    'secciones.eliminar_item_seguridad_charlas': 'secciones.seguridad_charla_eliminar',
    'secciones.editar_item_luminarias': 'secciones.editar_luminaria',
    'secciones.eliminar_item_luminarias': 'secciones.eliminar_luminaria',
    'secciones.editar_item_first_last': 'secciones.editar_first_last',
    'secciones.eliminar_item_first_last': 'secciones.eliminar_first_last',
    'secciones.editar_item_equipo_liviano': 'secciones.editar_equipo_liviano',
    'secciones.eliminar_item_equipo_liviano': 'secciones.eliminar_equipo_liviano',
    'secciones.editar_item_entrenamiento': 'secciones.editar_entrenamiento_personal',
    'secciones.eliminar_item_entrenamiento': 'secciones.eliminar_entrenamiento_personal',
    'secciones.editar_item_contactos': 'secciones.editar_contacto_operador',
    'secciones.eliminar_item_contactos': 'secciones.eliminar_contacto_operador'
}

for root, _, files in os.walk(template_dir):
    for file in files:
        if file.endswith('.html'):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                new_content = content
                for bad, good in CORRECTIONS.items():
                    # Reemplazar tanto con comillas simples como dobles
                    new_content = new_content.replace(f"url_for('{bad}'", f"url_for('{good}'")
                    new_content = new_content.replace(f'url_for("{bad}"', f'url_for("{good}"')
                
                if new_content != content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Fixed template: {file}")
            except Exception as e:
                print(f"Error processing {file}: {e}")
