import re

with open("static/app.js", encoding="utf-8") as f:
    js = f.read()

with open("static/index.html", encoding="utf-8") as f:
    html = f.read()

ids_in_js = sorted(list(set(re.findall(r'getElementById\(["\']([^"\']+)["\']\)', js))))
ids_in_html = set(re.findall(r'id=["\']([^"\']+)["\']', html))

missing = [x for x in ids_in_js if x not in ids_in_html]
print(f"Total IDs checked: {len(ids_in_js)}")
print(f"Missing IDs in HTML ({len(missing)}):")
for m in missing:
    print(" -", m)
