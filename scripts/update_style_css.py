with open("static/style.css", "r", encoding="utf-8") as f:
    css = f.read()

# Replace all var(--accent-cyan) and var(--accent-blue) with var(--accent-primary)
css = css.replace("var(--accent-cyan)", "var(--accent-primary)")
css = css.replace("var(--accent-blue)", "var(--accent-primary)")

# Replace dark mode --accent-cyan with #A100FF
css = css.replace("--accent-cyan: #c054ff;", "--accent-cyan: #A100FF;")

# Replace rgba(57, 197, 207, 0.05) in dropzone hover with var(--accent-purple-light)
css = css.replace("rgba(57, 197, 207, 0.05)", "var(--accent-purple-light)")
css = css.replace("rgba(57, 197, 207, 0.15)", "var(--accent-purple-light)")
css = css.replace("rgba(57, 197, 207, 0.25)", "rgba(161, 0, 255, 0.25)")
css = css.replace("rgba(56, 139, 253, 0.15)", "var(--accent-purple-light)")

# Ensure .theme-toggle-btn has border-radius: 50%
css = css.replace(
    """.theme-toggle-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: var(--radius-sm);""",
    """.theme-toggle-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 50%;"""
)

# Ensure input-card and verdict-sidebar styling
old_cards = """.input-card, .verdict-sidebar {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 18px;
}"""

new_cards = """.input-card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 18px;
}

.verdict-sidebar {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.verdict-summary-card,
.attack-detection-card,
.layer-timings-card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 18px;
  box-shadow: var(--shadow-sm);
}"""

if old_cards in css:
    css = css.replace(old_cards, new_cards)

# Add .badge-error if not present
if ".badge-error" not in css:
    badge_escalate_idx = css.find(".badge-escalate {")
    if badge_escalate_idx != -1:
        end_brace = css.find("}", badge_escalate_idx) + 1
        badge_error_css = """

.badge-error {
  background-color: var(--accent-amber-bg);
  color: var(--accent-amber);
  border: 1px solid var(--accent-amber);
  box-shadow: 0 0 10px rgba(210, 153, 34, 0.25);
}"""
        css = css[:end_brace] + badge_error_css + css[end_brace:]

# Ensure button primary hover is slightly darker purple per requirement
css = css.replace(
    """.btn-primary {
  background: linear-gradient(135deg, #A100FF 0%, #7d00c7 100%);
  color: #fff;
  box-shadow: 0 2px 8px rgba(161, 0, 255, 0.3);
}

.btn-primary:hover {
  background: linear-gradient(135deg, #b42eff 0%, #A100FF 100%);
  box-shadow: 0 0 14px rgba(161, 0, 255, 0.45);
}""",
    """.btn-primary {
  background: var(--accent-primary);
  color: #fff;
  box-shadow: 0 2px 8px rgba(161, 0, 255, 0.3);
}

.btn-primary:hover {
  background: var(--accent-primary-hover);
  box-shadow: 0 0 14px rgba(161, 0, 255, 0.45);
}"""
)

# Ensure attack-count-badge clean state has styles
if ".attack-count-badge.clean" not in css:
    threats_idx = css.find(".attack-count-badge.has-threats {")
    if threats_idx != -1:
        end_b = css.find("}", threats_idx) + 1
        clean_css = """

.attack-count-badge.clean {
  background-color: var(--accent-green-bg);
  color: var(--accent-green);
  border-color: rgba(16, 135, 58, 0.3);
}"""
        css = css[:end_b] + clean_css + css[end_b:]

with open("static/style.css", "w", encoding="utf-8") as f:
    f.write(css)

print("Updated style.css successfully!")
