import re

with open("static/style.css", encoding="utf-8") as f:
    lines = f.readlines()

for idx, line in enumerate(lines, 1):
    low = line.lower()
    if any(k in low for k in ["cyan", "teal", "blue", "#388", "#39c", "#58a", "#00d", "#1f6feb", "#238636"]):
        print(f"Line {idx}: {line.strip()}")
