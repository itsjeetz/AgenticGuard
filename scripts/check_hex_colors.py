import re

with open("static/style.css", encoding="utf-8") as f:
    text = f.read()

# Split into lines
lines = text.split("\n")
inside_vars = False
for idx, line in enumerate(lines, 1):
    stripped = line.strip()
    if stripped.startswith(":root") or stripped.startswith('[data-theme="dark"]'):
        inside_vars = True
    if inside_vars and stripped.startswith("}"):
        inside_vars = False
        continue
    if not inside_vars:
        hexes = re.findall(r'#(?:[0-9a-fA-F]{3}){1,2}\b', line)
        if hexes:
            print(f"Line {idx}: {hexes} -> {line.strip()}")
