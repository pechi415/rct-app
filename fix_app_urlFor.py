with open('app.py', 'r', encoding='utf-8') as file:
    content = file.read()

routes = [
    'ver_reportes', 'nuevo_reporte', 'reporte_inicio', 
    'cerrar_reporte', 'reabrir_reporte', 'editar_fecha_reporte', 
    'resumen', 'reporte_pdf', 'eliminar_reporte'
]

for r in routes:
    content = content.replace(f'url_for("{r}"', f'url_for("reportes.{r}"')
    content = content.replace(f"url_for('{r}'", f"url_for('reportes.{r}'")

with open('app.py', 'w', encoding='utf-8') as file:
    file.write(content)

print("Actualizados los url_for de reportes en app.py")
