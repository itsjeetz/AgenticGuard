import re

with open("static/app.js", encoding="utf-8") as f:
    js = f.read()

selectors = re.findall(r'querySelector(?:All)?\(["\']([^"\']+)["\']\)', js)
print(f"Total selectors: {len(selectors)}")
for s in sorted(set(selectors)):
    print(" -", s)
