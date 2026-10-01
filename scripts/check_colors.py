with open('static/style.css', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print('Total lines in style.css:', len(lines))
for i, line in enumerate(lines):
    # check for hardcoded colors
    lower = line.lower()
    for col in ['#39c5cf', '#388bfd', '#1f6feb', '#1158c7', '#0a0c10', '#12161f', '#1a202c', '#2b3340', '#e6edf3']:
        if col in lower and i > 50:  # skip root definitions
            print(f'Line {i+1}: {col} -> {line.strip()[:80]}')
