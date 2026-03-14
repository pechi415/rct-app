import glob
import re

for f in glob.glob('templates/*.html'):
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    matches = re.findall(r"url_for\(['\"]([^'\".]+)['\"]", content)
    missing = [m for m in matches if m != 'static']
    if missing:
        print(f"{f}: missing blueprint prefix: {missing}")
