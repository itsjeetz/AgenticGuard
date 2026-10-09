"""Read-only HTML renderer for the hidden /evidence route (§Q&A reference)."""

from datetime import datetime, timezone
import json
import math
from pathlib import Path
from typing import Any

from eval.claims_config import CLAIM_THRESHOLDS
from eval.claims import evaluate_claims


def wilson_score_interval(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Compute exact Wilson score interval for binomial proportions."""
    if n <= 0:
        return 0.0, 0.0
    z = 1.959963984540054  # 95% confidence
    p = k / n
    denom = 1 + (z * z) / n
    center = (p + (z * z) / (2 * n)) / denom
    half_width = (z * math.sqrt((p * (1 - p) / n) + (z * z) / (4 * n * n))) / denom
    lower = max(0.0, center - half_width)
    upper = min(1.0, center + half_width)
    return round(lower, 4), round(upper, 4)


def load_latest_report() -> dict[str, Any]:
    """Load latest evaluation report from reports/report.json."""
    report_file = Path("reports/report.json")
    if not report_file.exists():
        return {}
    try:
        return json.loads(report_file.read_text(encoding="utf-8"))
    except Exception:
        return {}


def render_evidence_html() -> str:
    """Generate self-contained, slide-ready HTML dashboard for /evidence."""
    report = load_latest_report()
    metadata = report.get("metadata", {})
    metrics = report.get("metrics", {})
    binary = metrics.get("binary", {})
    categories = metrics.get("categories", {})
    sources = metrics.get("sources", {})
    latency = metrics.get("latency", {}).get("total_ms", {})
    residual = metrics.get("sanitization", {}).get("residual_attack_rate", 0.0)

    # Evaluate position claims
    claims_eval = evaluate_claims(report) if report else {"claims": {}}
    claims = claims_eval.get("claims", {})

    f3_pass = claims.get("F3", {}).get("pass", False)
    f2_pass = claims.get("F2", {}).get("pass", False)
    f1_pass = claims.get("F1", {}).get("pass", False)
    d2_pass = claims.get("D2", {}).get("pass", False)
    d1_pass = claims.get("D1", {}).get("pass", False)

    feat_cell = "F3" if f3_pass else ("F2" if f2_pass else ("F1" if f1_pass else "F0"))
    depth_cell = "D2" if d2_pass else ("D1" if d1_pass else "D0")
    declared_cell = f"{feat_cell} x {depth_cell}"

    mode = metadata.get("mode", "rules_only")
    provider = metadata.get("provider", "rules_only")
    is_rules_only = "rules_only" in provider.lower() or mode == "rules_only"
    split = metadata.get("split", "dev").upper()
    total_items = metadata.get("total_items", metadata.get("items_evaluated", 0))
    commit = metadata.get("git_commit", "unknown")
    timestamp = metadata.get("timestamp", datetime.now(timezone.utc).isoformat())

    # Build category rows
    cat_rows = []
    for cat_name, cat_data in categories.items():
        n = cat_data.get("count", 0)
        flagged_rec = cat_data.get("flagged_recall", 0.0)
        corr_rec = cat_data.get("category_correct_recall", 0.0)
        k_flagged = round(flagged_rec * n)
        k_corr = round(corr_rec * n)
        ci_fl_low, ci_fl_high = wilson_score_interval(k_flagged, n)
        ci_cr_low, ci_cr_high = wilson_score_interval(k_corr, n)

        low_n = n < 15
        flag_pass = flagged_rec >= 0.80 and corr_rec >= 0.70 and not low_n
        status_badge = (
            '<span class="badge-pass">PASS</span>'
            if flag_pass
            else ('<span class="badge-warn">LOW N</span>' if low_n else '<span class="badge-fail">FAIL</span>')
        )

        cat_rows.append(f"""
        <tr>
          <td><strong>{cat_name}</strong></td>
          <td>{n}</td>
          <td>{flagged_rec * 100:.1f}% <span class="ci-text">[{ci_fl_low*100:.1f}%, {ci_fl_high*100:.1f}%]</span></td>
          <td>{corr_rec * 100:.1f}% <span class="ci-text">[{ci_cr_low*100:.1f}%, {ci_cr_high*100:.1f}%]</span></td>
          <td>{status_badge}</td>
        </tr>
        """)

    # Build source rows
    source_rows = []
    for src_name, src_data in sources.items():
        n = src_data.get("count", 0)
        rec = src_data.get("flagged_recall", src_data.get("recall", 0.0))
        fpr = src_data.get("benign_fpr", src_data.get("fpr", 0.0))
        atk_n = src_data.get("attack_count", round(n * 0.7))
        ben_n = src_data.get("benign_count", n - atk_n)

        ci_rec_low, ci_rec_high = wilson_score_interval(round(rec * atk_n), atk_n)
        ci_fpr_low, ci_fpr_high = wilson_score_interval(round(fpr * ben_n), ben_n)

        src_pass = rec >= 0.85 and fpr <= 0.05
        s_badge = '<span class="badge-pass">PASS</span>' if src_pass else '<span class="badge-fail">MONITOR</span>'

        source_rows.append(f"""
        <tr>
          <td><code>{src_name}</code></td>
          <td>{n} (Atk: {atk_n}, Ben: {ben_n})</td>
          <td>{rec * 100:.1f}% <span class="ci-text">[{ci_rec_low*100:.1f}%, {ci_rec_high*100:.1f}%]</span></td>
          <td>{fpr * 100:.1f}% <span class="ci-text">[{ci_fpr_low*100:.1f}%, {ci_fpr_high*100:.1f}%]</span></td>
          <td>{s_badge}</td>
        </tr>
        """)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgenticGuard — Offline Evidence & Declared Position</title>
  <style>
    :root {{
      --bg: #0f0c1b;
      --card-bg: #181428;
      --card-border: #2c2545;
      --text: #e6e2f5;
      --text-muted: #9f9ab3;
      --primary: #9d4edd;
      --primary-light: #c77dff;
      --green: #2ec4b6;
      --amber: #ff9f1c;
      --red: #e71d36;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --mono: "SF Mono", Consolas, "Liberation Mono", Menlo, Courier, monospace;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      line-height: 1.5;
      padding: 30px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 20px;
      margin-bottom: 25px;
    }}
    .header h1 {{ font-size: 24px; font-weight: 700; color: #fff; }}
    .header p {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; }}
    .badge-provisional {{
      background: rgba(255, 159, 28, 0.2);
      color: var(--amber);
      border: 1px solid var(--amber);
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 700;
    }}
    .badge-verified {{
      background: rgba(46, 196, 182, 0.2);
      color: var(--green);
      border: 1px solid var(--green);
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 700;
    }}
    .grid-summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 25px;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 18px;
    }}
    .card h3 {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; }}
    .card .val {{ font-size: 28px; font-weight: 800; color: #fff; margin-top: 6px; }}
    .card .sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
    .position-banner {{
      background: linear-gradient(135deg, rgba(157, 78, 221, 0.15), rgba(46, 196, 182, 0.1));
      border: 1px solid var(--primary);
      border-radius: 12px;
      padding: 20px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 25px;
    }}
    .position-banner .title {{ font-size: 14px; text-transform: uppercase; color: var(--primary-light); font-weight: 700; }}
    .position-banner .cell {{ font-size: 36px; font-weight: 900; color: #fff; }}
    .position-banner .note {{ font-size: 13px; color: var(--text-muted); max-width: 600px; }}
    .section-title {{ font-size: 18px; font-weight: 700; margin: 30px 0 15px 0; color: #fff; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 25px;
      background: var(--card-bg);
      border-radius: 10px;
      overflow: hidden;
      border: 1px solid var(--card-border);
    }}
    th, td {{
      padding: 12px 16px;
      text-align: left;
      font-size: 13px;
      border-bottom: 1px solid var(--card-border);
    }}
    th {{ background: #130f22; font-weight: 600; color: var(--text-muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
    tr:last-child td {{ border-bottom: none; }}
    code {{ font-family: var(--mono); font-size: 12px; background: rgba(255,255,255,0.06); padding: 2px 5px; border-radius: 4px; }}
    .ci-text {{ font-size: 11px; color: var(--text-muted); font-family: var(--mono); }}
    .badge-pass {{ color: var(--green); background: rgba(46, 196, 182, 0.15); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
    .badge-warn {{ color: var(--amber); background: rgba(255, 159, 28, 0.15); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
    .badge-fail {{ color: var(--red); background: rgba(231, 29, 54, 0.15); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
    .actions-bar {{ display: flex; gap: 12px; margin-top: 20px; }}
    .btn {{
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}
    .btn-primary {{ background: var(--primary); color: #fff; border: none; }}
    .btn-secondary {{ background: var(--card-bg); color: var(--text); border: 1px solid var(--card-border); }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>AgenticGuard — Offline Evidence & Declared Position</h1>
        <p>Official Hackathon Verification Document (§0 Rule 4: Claims come strictly from measurements).</p>
      </div>
      <div>
        {'<span class="badge-provisional">PROVISIONAL (RULES-ONLY BASELINE)</span>' if is_rules_only else '<span class="badge-verified">EVALUATED (FULL CASCADE)</span>'}
      </div>
    </div>

    <!-- Position Declaration Banner -->
    <div class="position-banner">
      <div>
        <div class="title">Official Declared Position (§Hackathon Grid)</div>
        <div class="cell">{declared_cell}</div>
      </div>
      <div class="note">
        <strong>Functional Breadth {feat_cell}:</strong> {claims.get(feat_cell, {}).get("description", "Empirically verified coverage.")}<br>
        <strong>Defense Depth {depth_cell}:</strong> {claims.get(depth_cell, {}).get("description", "Empirically verified reliability on text & structured carriers.")}<br>
        <em>Note: D3 (Universal Multimodal & OCR) is explicitly not claimed due to lack of local OCR pipeline.</em>
      </div>
    </div>

    <!-- Summary KPI Cards -->
    <div class="grid-summary">
      <div class="card">
        <h3>Benchmark Split & Scope</h3>
        <div class="val">{split} N={total_items}</div>
        <div class="sub">Git Commit: <code>{commit[:7]}</code></div>
      </div>
      <div class="card">
        <h3>Flagged Recall</h3>
        <div class="val">{binary.get("recall", 0.0) * 100:.1f}%</div>
        <div class="sub">{binary.get("tp", 0)} / {binary.get("total_attacks", 0)} attacks intercepted</div>
      </div>
      <div class="card">
        <h3>Benign False Positive Rate</h3>
        <div class="val">{binary.get("fpr", 0.0) * 100:.1f}%</div>
        <div class="sub">{binary.get("fp", 0)} / {binary.get("total_benign", 0)} benign blocked</div>
      </div>
      <div class="card">
        <h3>Latency (p95)</h3>
        <div class="val">{latency.get("p95", 0.0):.1f} ms</div>
        <div class="sub">Mean: {latency.get("mean", 0.0):.1f} ms</div>
      </div>
    </div>

    <!-- Category Performance Table -->
    <h2 class="section-title">Attack Type Category Coverage (F1–F3 Criteria)</h2>
    <table>
      <thead>
        <tr>
          <th>Attack Vector</th>
          <th>Sample Count (n)</th>
          <th>Flagged Recall (95% CI)</th>
          <th>Category-Correct Recall (95% CI)</th>
          <th>Status (F3: ≥80% / ≥70%)</th>
        </tr>
      </thead>
      <tbody>
        {"".join(cat_rows) if cat_rows else '<tr><td colspan="5">No category evaluations recorded</td></tr>'}
      </tbody>
    </table>

    <!-- Source / Carrier Performance Table -->
    <h2 class="section-title">Delivery Carrier & Format Reliability (D1–D2 Criteria)</h2>
    <table>
      <thead>
        <tr>
          <th>Input Channel / Format</th>
          <th>Sample Distribution</th>
          <th>Recall on Attacks (95% CI)</th>
          <th>Benign FPR (95% CI)</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {"".join(source_rows) if source_rows else '<tr><td colspan="5">No source evaluations recorded</td></tr>'}
      </tbody>
    </table>

    <!-- Navigation / Export Actions -->
    <div class="actions-bar">
      <a href="/api/eval/latest" class="btn btn-secondary" target="_blank">View Raw JSON Evidence</a>
      <a href="/api/eval/report-markdown" class="btn btn-secondary" target="_blank">View Raw EVAL_REPORT.md</a>
      <a href="/" class="btn btn-primary">Return to Main Firewall SOC</a>
    </div>
  </div>
</body>
</html>
"""
    return html
