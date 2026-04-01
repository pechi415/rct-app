import os

template_dir = r'c:\Users\Asus\Desktop\Python\rct_app\templates'

fixes = {
    r'/reportes/ r.id /supervisores/ it.id /editar': "url_for('secciones.editar_item_supervisores', reporte_id=r.id, item_id=it.id)",
    r'/reportes/ r.id /supervisores/eliminar/ it.id': "url_for('secciones.eliminar_item_supervisores', reporte_id=r.id, item_id=it.id)",
    
    r'/reportes/ r.id /seguridad/obs/ it.id /editar': "url_for('secciones.editar_item_seguridad_obs', reporte_id=r.id, item_id=it.id)",
    r'/reportes/ r.id /seguridad/obs/ it.id /eliminar': "url_for('secciones.eliminar_item_seguridad_obs', reporte_id=r.id, item_id=it.id)",
    
    r'/reportes/ r.id /seguridad/charla/ it.id /editar': "url_for('secciones.editar_item_seguridad_charlas', reporte_id=r.id, item_id=it.id)",
    r'/reportes/ r.id /seguridad/charla/ it.id /eliminar': "url_for('secciones.eliminar_item_seguridad_charlas', reporte_id=r.id, item_id=it.id)",
    
    r'/reportes/ r.id /luminarias/ it.id /editar': "url_for('secciones.editar_item_luminarias', reporte_id=r.id, item_id=it.id)",
    r'/reportes/ r.id /luminarias/eliminar/ it.id': "url_for('secciones.eliminar_item_luminarias', reporte_id=r.id, item_id=it.id)",
    
    r'/reportes/ r.id /gestion/ it.id /editar': "url_for('secciones.editar_item_gestion', reporte_id=r.id, item_id=it.id)",
    r'/reportes/ r.id /gestion/eliminar/ it.id': "url_for('secciones.eliminar_item_gestion', reporte_id=r.id, item_id=it.id)",
    
    r'/reportes/ r.id /first_last/editar': "url_for('secciones.editar_item_first_last', reporte_id=r.id)",
    r'/reportes/ r.id /first_last/eliminar': "url_for('secciones.eliminar_item_first_last', reporte_id=r.id)",
    
    r'/reportes/ r.id /equipo_liviano/ it.id /editar': "url_for('secciones.editar_item_equipo_liviano', reporte_id=r.id, item_id=it.id)",
    r'/reportes/ r.id /equipo_liviano/eliminar/ it.id': "url_for('secciones.eliminar_item_equipo_liviano', reporte_id=r.id, item_id=it.id)",
    
    r'/reportes/ r.id /entrenamiento/ it.id /editar': "url_for('secciones.editar_item_entrenamiento', reporte_id=r.id, item_id=it.id)",
    r'/reportes/ r.id /entrenamiento/eliminar/ it.id': "url_for('secciones.eliminar_item_entrenamiento', reporte_id=r.id, item_id=it.id)",
    
    r'/reportes/ r.id /contactos/ it.id /editar': "url_for('secciones.editar_item_contactos', reporte_id=r.id, item_id=it.id)",
    r'/reportes/ r.id /contactos/eliminar/ it.id': "url_for('secciones.eliminar_item_contactos', reporte_id=r.id, item_id=it.id)"
}

for root, dirs, files in os.walk(template_dir):
    for file in files:
        if file.endswith('.html'):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                new_content = content
                for bad, good in fixes.items():
                    new_content = new_content.replace(bad, good)
                    
                if new_content != content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Fixed {file}")
            except Exception as e:
                print(f"Error en {file}: {e}")
