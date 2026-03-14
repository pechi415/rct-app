import glob
import os

html_files = glob.glob('templates/*.html')
for f in html_files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # fix the url_for routes
    new_content = content.replace("url_for('admin_", "url_for('admin.admin_")
    
    if new_content != content:
        with open(f, 'w', encoding='utf-8') as file:
            file.write(new_content)
        print(f"Actualizado {f}")
