import re

with open('static/app.js', 'r', encoding='utf-8') as f:
    js_text = f.read()

with open('static/index.html', 'r', encoding='utf-8') as f:
    html_text = f.read()

# find all getElementById in JS
js_ids = re.findall(r'getElementById\(["\']([^"\']+)["\']\)', js_text)
html_ids = set(re.findall(r'id=["\']([^"\']+)["\']', html_text))

missing = []
for jid in sorted(set(js_ids)):
    if jid not in html_ids:
        missing.append(jid)

print('=== Missing IDs referenced by getElementById ===')
for m in missing:
    print('-', m)

# find all querySelector / querySelectorAll
qs_matches = re.findall(r'querySelector(?:All)?\(["\']([^"\']+)["\']\)', js_text)
print('\n=== All querySelector targets ===')
for q in sorted(set(qs_matches)):
    print('-', q)
